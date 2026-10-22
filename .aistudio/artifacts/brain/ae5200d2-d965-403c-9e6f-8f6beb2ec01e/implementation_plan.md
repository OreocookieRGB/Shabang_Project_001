# Side Quests: Architecture Blueprint & Implementation Plan (Spark Strict — Amended)

Side Quests is a private, invite-only, mobile-first web app for an 8-student university group at the National University of Science and Technology (NUST) in Bulawayo, Zimbabwe. It turns everyday campus life into a game of real-world challenges with tangible social stakes, photo evidence, group consensus voting, and a public punishment ledger.

All features are engineered strictly for **Firestore Standard Edition** on the **Firebase Spark Free Tier**. Stage 1 focuses exclusively on the **solo quest loop** (assigned and open), with group quests deferred to Stage 5 / v2 while preserving the `participantIds` schema field.

---

## 1. Amended Architecture & Helper Optimizations

### 1. `isApprovedMember` Helper (1 Callout)
By eliminating the redundant `exists()` call and checking `.data.status == 'active'` directly, `isApprovedMember` evaluates in exactly **1 callout** per document write:
```javascript
function isApprovedMember(groupId) {
  return isSignedIn() &&
    get(/databases/$(database)/documents/groups/$(groupId)/members/$(request.auth.uid)).data.status == 'active';
}
```

### 2. Stage 1 Scope: Solo-Only Quests
- Group quests move to v2 (Stage 5 Duels/Bounties).
- Stage 1 supports:
  - **Solo Assigned**: Created with `assigneeId` and `participantIds == [assigneeId]`.
  - **Solo Open**: Created with `assigneeId == null` and `participantIds == []`; on accept, `assigneeId` and `participantIds` become `[acceptorUid]`.
- All multi-taker settlement and group creation logic is removed from v1 rules, eliminating batch callout overhead.

### 3. Member Leaving Invariant
A member can leave the group (`status: 'left'`) **only if** `existing().activeQuestCount == 0`. A player cannot leave while holding pending quests.

### 4. Independent Document Security
Firestore evaluates each document write independently. The `/ledger` create rule calls `isApprovedMember('nust_squad')` directly (1 callout) alongside its quest and deduplication checks.

---

## 2. Full Security Rules Specification (Stage 1 Solo-Strict)

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // 0. Default Deny Catch-all
    match /{document=**} {
      allow read, write: if false;
    }

    function isSignedIn() {
      return request.auth != null && request.auth.token.email_verified == true;
    }

    // 1 callout only (no redundant exists())
    function isApprovedMember(groupId) {
      return isSignedIn() &&
        get(/databases/$(database)/documents/groups/$(groupId)/members/$(request.auth.uid)).data.status == 'active';
    }

    function isGroupAdmin(groupId) {
      return isApprovedMember(groupId) &&
        get(/databases/$(database)/documents/groups/$(groupId)/members/$(request.auth.uid)).data.role == 'admin';
    }

    function incoming() {
      return request.resource.data;
    }

    function existing() {
      return resource.data;
    }

    function calculatePoints(data) {
      let base = data.difficulty == 'easy' ? 10 : (data.difficulty == 'medium' ? 25 : 50);
      let mult = data.deadlineHours < 6 ? 1.5 : (data.deadlineHours <= 48 ? 1.0 : 0.75);
      return (mult == 1.5 && (
        (base == 10 && data.calculatedPoints == 15) ||
        (base == 25 && data.calculatedPoints == 38) ||
        (base == 50 && data.calculatedPoints == 75)
      )) ||
      (mult == 1.0 && data.calculatedPoints == base) ||
      (mult == 0.75 && (
        (base == 10 && data.calculatedPoints == 8) ||
        (base == 25 && data.calculatedPoints == 19) ||
        (base == 50 && data.calculatedPoints == 38)
      ));
    }

    function isValidAvatar(cfg) {
      return cfg is map && cfg.size() <= 12 &&
        cfg.keys().hasOnly(['sex', 'faceColor', 'earSize', 'hairStyle', 'hairColor', 'eyeStyle', 'glassesStyle', 'noseStyle', 'mouthStyle', 'shirtStyle', 'shirtColor', 'bgColor']);
    }

    // =========================================================================
    // 1. GROUP & MEMBERSHIP
    // =========================================================================
    match /groups/{groupId} {
      allow read: if isApprovedMember(groupId);

      allow update: if isApprovedMember(groupId) && (
        (isGroupAdmin(groupId) && incoming().diff(existing()).affectedKeys().hasOnly(['inviteCode', 'updatedAt'])) ||
        (incoming().diff(existing()).affectedKeys().hasOnly(['memberCount', 'lastMemberChange', 'updatedAt']) &&
          incoming().lastMemberChange != null &&
          isValidGroupMemberCountDelta(groupId, incoming().lastMemberChange))
      );

      match /members/{memberId} {
        allow read: if isApprovedMember(groupId);

        allow create: if isGroupAdmin(groupId)
          && incoming().userId == memberId
          && incoming().role == 'member'
          && incoming().status == 'active'
          && incoming().totalPoints == 0
          && incoming().activeQuestCount == 0
          && incoming().lastQuestId == null
          && incoming().joinedAt == request.time
          && incoming().lastActiveAt == request.time
          && existsAfter(/databases/$(database)/documents/groups/$(groupId)/join_requests/$(memberId))
          && getAfter(/databases/$(database)/documents/groups/$(groupId)/join_requests/$(memberId)).data.status == 'approved'
          && getAfter(/databases/$(database)/documents/groups/$(groupId)).data.lastMemberChange == memberId
          && getAfter(/databases/$(database)/documents/groups/$(groupId)).data.memberCount == get(/databases/$(database)/documents/groups/$(groupId)).data.memberCount + 1;

        allow update: if isApprovedMember(groupId) && (
          // Self ping: lastActiveAt only
          (request.auth.uid == memberId && incoming().diff(existing()).affectedKeys().hasOnly(['lastActiveAt']) && incoming().lastActiveAt == request.time) ||
          // Member Leaving: Must have activeQuestCount == 0
          ((request.auth.uid == memberId || (isGroupAdmin(groupId) && existing().role != 'admin')) &&
            incoming().diff(existing()).affectedKeys().hasOnly(['status', 'updatedAt']) &&
            existing().status == 'active' && incoming().status == 'left' &&
            existing().activeQuestCount == 0 &&
            getAfter(/databases/$(database)/documents/groups/$(groupId)).data.lastMemberChange == memberId &&
            getAfter(/databases/$(database)/documents/groups/$(groupId)).data.memberCount == get(/databases/$(database)/documents/groups/$(groupId)).data.memberCount - 1) ||
          // Member Rejoining
          (isGroupAdmin(groupId) && existing().status == 'left' &&
            incoming().diff(existing()).affectedKeys().hasOnly(['status', 'activeQuestCount', 'lastActiveAt', 'updatedAt']) &&
            incoming().status == 'active' &&
            incoming().activeQuestCount == 0 &&
            incoming().lastActiveAt == request.time &&
            getAfter(/databases/$(database)/documents/groups/$(groupId)).data.lastMemberChange == memberId &&
            getAfter(/databases/$(database)/documents/groups/$(groupId)).data.memberCount == get(/databases/$(database)/documents/groups/$(groupId)).data.memberCount + 1) ||
          // Quest Transition Update
          (incoming().diff(existing()).affectedKeys().hasOnly(['totalPoints', 'activeQuestCount', 'lastQuestId']) &&
            incoming().lastQuestId != null &&
            isValidMemberQuestDelta(groupId, memberId, incoming().lastQuestId))
        );
      }

      match /join_requests/{requestId} {
        allow read: if isSignedIn() && (requestId == request.auth.uid || isGroupAdmin(groupId));
        allow create: if isSignedIn() && requestId == request.auth.uid
          && incoming().status == 'pending'
          && incoming().requestedAt == request.time
          && incoming().inviteCode == get(/databases/$(database)/documents/groups/$(groupId)).data.inviteCode;
        allow update: if isGroupAdmin(groupId)
          && incoming().diff(existing()).affectedKeys().hasOnly(['status', 'approvedBy', 'updatedAt'])
          && incoming().status in ['approved', 'rejected']
          && incoming().approvedBy == request.auth.uid;
      }
    }

    function isValidGroupMemberCountDelta(groupId, memId) {
      let memBeforeExists = exists(/databases/$(database)/documents/groups/$(groupId)/members/$(memId));
      let memAfter = getAfter(/databases/$(database)/documents/groups/$(groupId)/members/$(memId)).data;

      return (
        (!memBeforeExists && memAfter.status == 'active' && incoming().memberCount == existing().memberCount + 1) ||
        (memBeforeExists && get(/databases/$(database)/documents/groups/$(groupId)/members/$(memId)).data.status == 'active' &&
         memAfter.status == 'left' && incoming().memberCount == existing().memberCount - 1) ||
        (memBeforeExists && get(/databases/$(database)/documents/groups/$(groupId)/members/$(memId)).data.status == 'left' &&
         memAfter.status == 'active' && incoming().memberCount == existing().memberCount + 1)
      );
    }

    function isValidMemberQuestDelta(groupId, memberId, qId) {
      let questAfter = getAfter(/databases/$(database)/documents/quests/$(qId)).data;
      let questBeforeExists = exists(/databases/$(database)/documents/quests/$(qId));
      let pts = questAfter.calculatedPoints;

      // Solo taker check
      let isTaker = questAfter.assigneeId == memberId;

      return isTaker && (
        // 1. Direct Assignment Create: (!exists -> 'active') -> activeQuestCount + 1
        (!questBeforeExists && questAfter.status == 'active' &&
          incoming().activeQuestCount == existing().activeQuestCount + 1 && incoming().activeQuestCount <= 2 &&
          incoming().totalPoints == existing().totalPoints) ||
        // 2. Open Quest Accepted: ('open' -> 'active') -> activeQuestCount + 1
        (questBeforeExists && get(/databases/$(database)/documents/quests/$(qId)).data.status == 'open' &&
          questAfter.status == 'active' &&
          incoming().activeQuestCount == existing().activeQuestCount + 1 && incoming().activeQuestCount <= 2 &&
          incoming().totalPoints == existing().totalPoints) ||
        // 3. Quest Passed: ('voting' -> 'passed') -> totalPoints + pts, activeQuestCount - 1
        (questBeforeExists && get(/databases/$(database)/documents/quests/$(qId)).data.status == 'voting' &&
          questAfter.status == 'passed' &&
          incoming().totalPoints == existing().totalPoints + pts &&
          incoming().activeQuestCount == existing().activeQuestCount - 1) ||
        // 4. Quest Failed via Refusal or Abandonment: ('active'/'open' -> 'failed') -> totalPoints - pts, activeQuestCount - 1
        (questBeforeExists && get(/databases/$(database)/documents/quests/$(qId)).data.status in ['active', 'open'] &&
          questAfter.status == 'failed' && questAfter.failReason in ['refused', 'abandoned'] &&
          incoming().totalPoints == existing().totalPoints - pts &&
          incoming().activeQuestCount == existing().activeQuestCount - 1) ||
        // 5. Quest Failed via Deadline or Vote: ('active'/'voting' -> 'failed') -> totalPoints unchanged, activeQuestCount - 1
        (questBeforeExists && get(/databases/$(database)/documents/quests/$(qId)).data.status in ['active', 'voting'] &&
          questAfter.status == 'failed' && questAfter.failReason in ['deadline', 'vote'] &&
          incoming().totalPoints == existing().totalPoints &&
          incoming().activeQuestCount == existing().activeQuestCount - 1) ||
        // 6. Quest Cancelled via Veto: ('active'/'veto_review' -> 'cancelled') -> totalPoints unchanged, activeQuestCount - 1
        (questBeforeExists && get(/databases/$(database)/documents/quests/$(qId)).data.status in ['active', 'veto_review'] &&
          questAfter.status == 'cancelled' &&
          incoming().totalPoints == existing().totalPoints &&
          incoming().activeQuestCount == existing().activeQuestCount - 1)
      );
    }

    // =========================================================================
    // 2. USERNAMES & PROFILES
    // =========================================================================
    match /usernames/{lowercaseHandle} {
      allow read: if isApprovedMember('nust_squad');

      allow create: if isSignedIn()
        && (isApprovedMember('nust_squad') || (
          exists(/databases/$(database)/documents/groups/nust_squad/join_requests/$(request.auth.uid)) &&
          get(/databases/$(database)/documents/groups/nust_squad/join_requests/$(request.auth.uid)).data.status == 'approved'
        ))
        && incoming().uid == request.auth.uid
        && incoming().createdAt == request.time
        && existsAfter(/databases/$(database)/documents/users/$(request.auth.uid))
        && getAfter(/databases/$(database)/documents/users/$(request.auth.uid)).data.usernameHandle == lowercaseHandle;
    }

    match /users/{userId} {
      allow read: if isApprovedMember('nust_squad');
      allow create: if isSignedIn() && request.auth.uid == userId
        && incoming().displayName is string
        && incoming().displayName.size() >= 3 && incoming().displayName.size() <= 20
        && incoming().usernameHandle == incoming().displayName.lower()
        && isValidAvatar(incoming().avatarConfig)
        && existsAfter(/databases/$(database)/documents/usernames/$(incoming().usernameHandle))
        && getAfter(/databases/$(database)/documents/usernames/$(incoming().usernameHandle)).data.uid == request.auth.uid;
      allow update: if isSignedIn() && request.auth.uid == userId
        && incoming().diff(existing()).affectedKeys().hasOnly(['avatarConfig', 'updatedAt'])
        && isValidAvatar(incoming().avatarConfig);
    }

    match /users_private/{userId} {
      allow read, write: if isSignedIn() && request.auth.uid == userId;
    }

    // =========================================================================
    // 3. QUESTS & TRANSITIONS (Solo-Only for Stage 1)
    // =========================================================================
    match /quests/{questId} {
      allow read: if isApprovedMember('nust_squad');

      allow create: if isApprovedMember('nust_squad')
        && incoming().id == questId
        && incoming().creatorId == request.auth.uid
        && incoming().type in ['assigned', 'open']
        && incoming().mode == 'solo'
        && incoming().title.size() >= 3 && incoming().title.size() <= 80
        && incoming().description.size() >= 10 && incoming().description.size() <= 500
        && incoming().punishmentText.size() >= 5 && incoming().punishmentText.size() <= 140
        && incoming().punishmentMoney >= 0 && incoming().punishmentMoney <= 5
        && incoming().deadlineHours >= 1 && incoming().deadlineHours <= 168
        && incoming().deadlineAt == request.time + duration.value(incoming().deadlineHours, 'h')
        && incoming().yesVotes == 0 && incoming().noVotes == 0
        && incoming().vetoYes == 0 && incoming().vetoKeep == 0
        && incoming().failReason == null
        && incoming().createdAt == request.time
        && calculatePoints(incoming())
        && (
          // Solo Assigned
          (incoming().type == 'assigned' && incoming().assigneeId != null &&
            incoming().participantIds == [incoming().assigneeId] &&
            incoming().status == 'active' &&
            isAssigneeReady(incoming().assigneeId, questId)) ||
          // Solo Open
          (incoming().type == 'open' && incoming().assigneeId == null &&
            incoming().participantIds == [] && incoming().status == 'open')
        );

      allow update: if isApprovedMember('nust_squad') && (
        (incoming().status == 'active' && existing().status == 'open' && isAcceptAction(questId)) ||
        (incoming().status == 'voting' && existing().status == 'active' && isProofSubmission(questId)) ||
        (incoming().status in ['active', 'veto_review'] && isVetoVoteAction(questId)) ||
        (existing().status == 'veto_review' && isVetoResolution(questId)) ||
        (incoming().status == 'failed' && existing().status in ['active', 'open'] && isAbandonAction(questId)) ||
        (existing().status == 'voting' && incoming().status == 'voting' && isVoteAction(questId)) ||
        (isLazyEvaluationAction(questId))
      );

      match /proof/{proofId} {
        allow read: if isApprovedMember('nust_squad');
        allow create: if isApprovedMember('nust_squad')
          && proofId == questId
          && request.auth.uid == get(/databases/$(database)/documents/quests/$(questId)).data.assigneeId
          && get(/databases/$(database)/documents/quests/$(questId)).data.status == 'active'
          && request.time <= get(/databases/$(database)/documents/quests/$(questId)).data.deadlineAt
          && incoming().photoBase64.size() <= 250000
          && incoming().consentAcknowledged == true
          && incoming().submittedBy == request.auth.uid
          && incoming().submittedAt == request.time;
        allow update, delete: if false;
      }

      match /votes/{voterId} {
        allow read: if isApprovedMember('nust_squad');
        allow create: if isApprovedMember('nust_squad')
          && voterId == request.auth.uid
          && request.auth.uid != get(/databases/$(database)/documents/quests/$(questId)).data.assigneeId
          && request.time <= get(/databases/$(database)/documents/quests/$(questId)).data.votingClosesAt
          && incoming().vote in ['yes', 'no']
          && incoming().votedAt == request.time;
        allow update, delete: if false;
      }

      match /veto_votes/{voterId} {
        allow read: if isApprovedMember('nust_squad');
        allow create: if isApprovedMember('nust_squad')
          && voterId == request.auth.uid
          && request.auth.uid != get(/databases/$(database)/documents/quests/$(questId)).data.assigneeId
          && get(/databases/$(database)/documents/quests/$(questId)).data.status in ['active', 'veto_review']
          && incoming().vote in ['cancel', 'keep']
          && incoming().votedAt == request.time;
        allow update, delete: if false;
      }
    }

    function isAssigneeReady(uid, qId) {
      return get(/databases/$(database)/documents/groups/nust_squad/members/$(uid)).data.status == 'active' &&
        get(/databases/$(database)/documents/groups/nust_squad/members/$(uid)).data.activeQuestCount < 2 &&
        getAfter(/databases/$(database)/documents/groups/nust_squad/members/$(uid)).data.activeQuestCount ==
          get(/databases/$(database)/documents/groups/nust_squad/members/$(uid)).data.activeQuestCount + 1 &&
        getAfter(/databases/$(database)/documents/groups/nust_squad/members/$(uid)).data.lastQuestId == qId;
    }

    function isAcceptAction(questId) {
      return existing().assigneeId == null
        && incoming().assigneeId == request.auth.uid
        && incoming().participantIds == [request.auth.uid]
        && incoming().diff(existing()).affectedKeys().hasOnly(['status', 'assigneeId', 'participantIds', 'updatedAt'])
        && isAssigneeReady(request.auth.uid, questId);
    }

    function isProofSubmission(questId) {
      let isTaker = request.auth.uid == existing().assigneeId;
      let expectedEligible = get(/databases/$(database)/documents/groups/nust_squad).data.memberCount - 1;

      return isTaker && request.time <= existing().deadlineAt
        && incoming().proofSubmittedAt == request.time
        && incoming().votingClosesAt == request.time + duration.value(24, 'h')
        && incoming().totalEligibleVoters == expectedEligible
        && incoming().diff(existing()).affectedKeys().hasOnly(['status', 'proofSubmittedAt', 'votingClosesAt', 'totalEligibleVoters', 'updatedAt'])
        && existsAfter(/databases/$(database)/documents/quests/$(questId)/proof/$(questId));
    }

    function isVetoVoteAction(questId) {
      let isTaker = request.auth.uid == existing().assigneeId;
      let vDoc = getAfter(/databases/$(database)/documents/quests/$(questId)/veto_votes/$(request.auth.uid)).data;

      return !isTaker && !exists(/databases/$(database)/documents/quests/$(questId)/veto_votes/$(request.auth.uid))
        && existsAfter(/databases/$(database)/documents/quests/$(questId)/veto_votes/$(request.auth.uid))
        && (
          (vDoc.vote == 'cancel' && incoming().vetoYes == existing().vetoYes + 1 && incoming().vetoKeep == existing().vetoKeep) ||
          (vDoc.vote == 'keep' && incoming().vetoKeep == existing().vetoKeep + 1 && incoming().vetoYes == existing().vetoYes)
        )
        && (
          (existing().status == 'active' && incoming().status == 'veto_review' && incoming().vetoStartedAt == request.time &&
           incoming().diff(existing()).affectedKeys().hasOnly(['status', 'vetoYes', 'vetoKeep', 'vetoStartedAt', 'updatedAt'])) ||
          (existing().status == 'veto_review' && incoming().status == 'veto_review' &&
           incoming().diff(existing()).affectedKeys().hasOnly(['vetoYes', 'vetoKeep', 'updatedAt']))
        );
    }

    function isVetoResolution(questId) {
      let groupMembers = get(/databases/$(database)/documents/groups/nust_squad).data.memberCount;
      let eligible = groupMembers - 1;

      return (
        // A. Veto Passes: vetoYes > eligible / 2 -> status: 'cancelled'
        (incoming().status == 'cancelled' && existing().vetoYes > (eligible / 2) &&
         incoming().diff(existing()).affectedKeys().hasOnly(['status', 'updatedAt']) &&
         verifyTerminalTakerUpdates(questId)) ||
        // B. Veto Fails/Dismissed: allowed if 24h passed OR vetoKeep >= eligible - (eligible / 2)
        (incoming().status == 'active' &&
         (request.time > existing().vetoStartedAt + duration.value(24, 'h') ||
          existing().vetoKeep >= (eligible - (eligible / 2))) &&
         incoming().deadlineAt == existing().deadlineAt + (request.time - existing().vetoStartedAt) &&
         incoming().diff(existing()).affectedKeys().hasOnly(['status', 'deadlineAt', 'updatedAt']))
      );
    }

    function isAbandonAction(questId) {
      let isTaker = request.auth.uid == existing().assigneeId;
      return isTaker && incoming().failReason in ['refused', 'abandoned']
        && incoming().diff(existing()).affectedKeys().hasOnly(['status', 'failReason', 'updatedAt'])
        && verifyTerminalTakerUpdates(questId)
        && verifyTerminalLedgerUpdates(questId);
    }

    function isVoteAction(questId) {
      let isTaker = request.auth.uid == existing().assigneeId;
      let voteDoc = getAfter(/databases/$(database)/documents/quests/$(questId)/votes/$(request.auth.uid)).data;

      return !isTaker && request.time <= existing().votingClosesAt
        && !exists(/databases/$(database)/documents/quests/$(questId)/votes/$(request.auth.uid))
        && existsAfter(/databases/$(database)/documents/quests/$(questId)/votes/$(request.auth.uid))
        && (
          (voteDoc.vote == 'yes' && incoming().yesVotes == existing().yesVotes + 1 && incoming().noVotes == existing().noVotes) ||
          (voteDoc.vote == 'no' && incoming().noVotes == existing().noVotes + 1 && incoming().yesVotes == existing().yesVotes)
        )
        && incoming().diff(existing()).affectedKeys().hasOnly(['yesVotes', 'noVotes', 'updatedAt']);
    }

    function isLazyEvaluationAction(questId) {
      return (
        // 1. Deadline Missed
        (existing().status == 'active' && request.time > existing().deadlineAt && incoming().status == 'failed' &&
         incoming().failReason == 'deadline' &&
         incoming().diff(existing()).affectedKeys().hasOnly(['status', 'failReason', 'updatedAt']) &&
         verifyTerminalTakerUpdates(questId) && verifyTerminalLedgerUpdates(questId)) ||
        // 2. Voting Closes: Passed
        (existing().status == 'voting' && request.time > existing().votingClosesAt &&
         existing().yesVotes > (existing().totalEligibleVoters / 2) && incoming().status == 'passed' &&
         incoming().diff(existing()).affectedKeys().hasOnly(['status', 'updatedAt']) &&
         verifyTerminalTakerUpdates(questId)) ||
        // 3. Voting Closes: Failed
        (existing().status == 'voting' && request.time > existing().votingClosesAt &&
         existing().yesVotes <= (existing().totalEligibleVoters / 2) && incoming().status == 'failed' &&
         incoming().failReason == 'vote' &&
         incoming().diff(existing()).affectedKeys().hasOnly(['status', 'failReason', 'updatedAt']) &&
         verifyTerminalTakerUpdates(questId) && verifyTerminalLedgerUpdates(questId))
      );
    }

    function verifyTerminalTakerUpdates(qId) {
      let quest = getAfter(/databases/$(database)/documents/quests/$(qId)).data;
      return (
        getAfter(/databases/$(database)/documents/groups/nust_squad/members/$(quest.assigneeId)).data.lastQuestId == qId &&
        getAfter(/databases/$(database)/documents/groups/nust_squad/members/$(quest.assigneeId)).data.activeQuestCount ==
          get(/databases/$(database)/documents/groups/nust_squad/members/$(quest.assigneeId)).data.activeQuestCount - 1
      );
    }

    function verifyTerminalLedgerUpdates(qId) {
      let quest = getAfter(/databases/$(database)/documents/quests/$(qId)).data;
      return existsAfter(/databases/$(database)/documents/ledger/$(qId + '_' + quest.assigneeId));
    }

    // =========================================================================
    // 4. LEDGER (Solo Deterministic ID: {questId}_{debtorId})
    // =========================================================================
    match /ledger/{entryId} {
      allow read: if isApprovedMember('nust_squad');

      // Evaluated independently per document (isApprovedMember costs 1 callout)
      allow create: if isApprovedMember('nust_squad')
        && entryId == (incoming().questId + '_' + incoming().debtorId)
        && !exists(/databases/$(database)/documents/ledger/$(entryId))
        && existsAfter(/databases/$(database)/documents/quests/$(incoming().questId))
        && getAfter(/databases/$(database)/documents/quests/$(incoming().questId)).data.status == 'failed'
        && incoming().debtorId == getAfter(/databases/$(database)/documents/quests/$(incoming().questId)).data.assigneeId
        && incoming().punishmentText == getAfter(/databases/$(database)/documents/quests/$(incoming().questId)).data.punishmentText
        && incoming().amountMoney == getAfter(/databases/$(database)/documents/quests/$(incoming().questId)).data.punishmentMoney
        && incoming().status == 'owed'
        && incoming().markedPaidBy == null
        && incoming().markedPaidAt == null
        && incoming().createdAt == request.time;

      allow update: if isApprovedMember('nust_squad')
        && incoming().diff(existing()).affectedKeys().hasOnly(['status', 'markedPaidBy', 'markedPaidAt'])
        && existing().status == 'owed'
        && incoming().status == 'paid'
        && incoming().markedPaidBy == request.auth.uid
        && incoming().markedPaidAt == request.time;
    }
  }
}
```

---

## 3. Recounted Document Callout Limits Audit (1 Callout `isApprovedMember`)

### Zero-Cache Accounting
- `isApprovedMember(groupId)` = **1 callout** (`get(/groups/{id}/members/{uid})`).
- Branch guards evaluate static fields first; failed branches evaluate **0 callouts**.

### Recounted Audit Table (All Operations in Stage 1)

| Batch Operation | Docs Written | Itemized Callouts per Document | Total Batch Callouts | Status ($\le 20$) |
| :--- | :--- | :--- | :--- | :--- |
| **1. Direct Assign Solo Create** | 1 Quest, 1 Member | **Quest**: `isApproved` (1) + `get(mem)` (1) + `getAfter(mem)` (1) = **3**<br>**Member**: `isApproved` (1) + `getAfter(quest)` (1) = **2** | **5 callouts** | PASS (Margin 15) |
| **2. Accept Open Quest** | 1 Quest, 1 Member | **Quest**: `isApproved` (1) + `get(mem)` (1) + `getAfter(mem)` (1) = **3**<br>**Member**: `isApproved` (1) + `exists(q)` (1) + `get(q)` (1) + `getAfter(q)` (1) = **4** | **7 callouts** | PASS (Margin 13) |
| **3. Proof Submission** | 1 Quest, 1 Proof | **Quest**: `isApproved` (1) + `get(grp)` (1) + `existsAfter(proof)` (1) = **3**<br>**Proof**: `isApproved` (1) + `get(quest)` (1) = **2** | **5 callouts** | PASS (Margin 15) |
| **4. Cast Vote** | 1 Quest, 1 Vote | **Quest**: `isApproved` (1) + `getAfter(vote)` (1) + `!exists(vote)` (1) + `existsAfter(vote)` (1) = **4**<br>**Vote**: `isApproved` (1) + `get(quest)` (1) = **2** | **6 callouts** | PASS (Margin 14) |
| **5. Cast Veto Vote** | 1 Quest, 1 VetoVote | **Quest**: `isApproved` (1) + `getAfter(vVote)` (1) + `!exists(vVote)` (1) + `existsAfter(vVote)` (1) = **4**<br>**VetoVote**: `isApproved` (1) + `get(quest)` (1) = **2** | **6 callouts** | PASS (Margin 14) |
| **6. Solo Pass** | 1 Quest, 1 Member | **Quest**: `isApproved` (1) + `getAfter(quest)` (1) + `getAfter(mem)` (1) + `get(mem)` (1) = **4**<br>**Member**: `isApproved` (1) + `exists(q)` (1) + `get(q)` (1) + `getAfter(q)` (1) = **4** | **8 callouts** | PASS (Margin 12) |
| **7. Solo Fail (Abandon / Lazy / Deadline)** | 1 Quest, 1 Member, 1 Ledger | **Quest**: `isApproved` (1) + `getAfter(quest)` (1) + `getAfter(mem)` (1) + `get(mem)` (1) + `existsAfter(ledger)` (1) = **5**<br>**Member**: `isApproved` (1) + `exists(q)` (1) + `get(q)` (1) + `getAfter(q)` (1) = **4**<br>**Ledger**: `isApproved` (1) + `!exists(self)` (1) + `existsAfter(q)` (1) = **3** | **12 callouts** | PASS (Margin 8) |
| **8. Member Status Change (Join / Leave)** | 1 Group, 1 Member | **Group**: `isApproved` (1) + `get(mem)` (1) + `getAfter(mem)` (1) = **3**<br>**Member**: `isApproved` (1) + `get(grp)` (1) + `getAfter(grp)` (1) = **3** | **6 callouts** | PASS (Margin 14) |

*Conclusion*: All Stage 1 operations evaluate between **5 and 12 callouts**. No operation comes within 3 of the 20-callout limit (the highest is Solo Fail at 12, leaving a safety margin of 8).

---

## 4. Updated Steps & Automated Emulator Test Suite

### Step 0.2: Security Rules & Automated Emulator Suite (Lead Collaborator 1)
- **Action**: Install `@firebase/rules-unit-testing`. Deploy `firestore.rules`. Implement `tests/rules.test.ts` running in the Firebase Local Emulator.
- **First Priority Emulator Test**:
  - **Solo-Fail Batch Test**: Submits an atomic batch containing:
    1. Quest transitioning from `'active'` $\rightarrow$ `'failed'` (`failReason: 'refused'`)
    2. Member transitioning `totalPoints - calculatedPoints`, `activeQuestCount - 1`, `lastQuestId == qId`
    3. Ledger document `{questId}_{debtorId}` created with status `'owed'`
    - Asserts operation succeeds and verifies total callout count evaluated is strictly $\le 12$ (within the 20 limit).
- **Secondary Automated Attack Tests in Step 0.2**:
  - Resolving a quest without changing the taker's member doc (`activeQuestCount - 1` missing) $\rightarrow$ `PERMISSION_DENIED`.
  - Member attempting to leave group when `activeQuestCount > 0` $\rightarrow$ `PERMISSION_DENIED`.
  - Non-member reading `/quests` or `/groups/nust_squad/members` $\rightarrow$ `PERMISSION_DENIED`.
  - Non-admin approving join request $\rightarrow$ `PERMISSION_DENIED`.
  - Updating `memberCount` directly without `lastMemberChange` pointing to transitioning member $\rightarrow$ `PERMISSION_DENIED`.
  - Creating a group quest in v1 (`mode == 'group'`) $\rightarrow$ `PERMISSION_DENIED`.
  - Assignee casting a veto vote on their own quest $\rightarrow$ `PERMISSION_DENIED`.
  - Freeze a quest with 1 cancel vote while majority votes keep $\rightarrow$ `PERMISSION_DENIED`.
  - Claiming a second username doc while user profile already has an existing `usernameHandle` $\rightarrow$ `PERMISSION_DENIED`.
