# ✨ So you want to run an audit

This `README.md` contains a set of checklists for our audit collaboration. This is your audit repo, which is used for scoping your audit and for providing information to wardens

Some of the checklists in this doc are for our scouts and some of them are for **you as the audit sponsor (⭐️)**.

---

# Repo setup

## ⭐️ Sponsor: Add code to this repo

- [ ] Create a PR to this repo with the below changes:
- [ ] Confirm that this repo is a self-contained repository with working commands that will build (at least) all in-scope contracts, and commands that will run tests producing gas reports for the relevant contracts.
- [ ] Please have final versions of contracts and documentation added/updated in this repo **no less than 48 business hours prior to audit start time.**
- [ ] Be prepared for a 🚨code freeze🚨 for the duration of the audit — important because it establishes a level playing field. We want to ensure everyone's looking at the same code, no matter when they look during the audit. (Note: this includes your own repo, since a PR can leak alpha to our wardens!)

## ⭐️ Sponsor: Repo checklist

- [ ] Modify the [Overview](#overview) section of this `README.md` file. Describe how your code is supposed to work with links to any relevant documentation and any other criteria/details that the auditors should keep in mind when reviewing. (Here are two well-constructed examples: [Ajna Protocol](https://github.com/code-423n4/2023-05-ajna) and [Maia DAO Ecosystem](https://github.com/code-423n4/2023-05-maia))
- [ ] Optional: pre-record a high-level overview of your protocol (not just specific smart contract functions). This saves wardens a lot of time wading through documentation.
- [ ] Review and confirm the details created by the Scout (technical reviewer) who was assigned to your contest. *Note: any files not listed as "in scope" will be considered out of scope for the purposes of judging, even if the file will be part of the deployed contracts.*  

---

# Sponsorname audit details
- Total Prize Pool: XXX XXX USDC (Notion: Total award pool)
  - HM awards: up to XXX XXX USDC (Notion: HM (main) pool)
    - If no valid Highs or Mediums are found, the HM pool is $0 
  - QA awards: XXX XXX USDC (Notion: QA pool)
  - Judge awards: XXX XXX USDC (Notion: Judge Fee)
  - Scout awards: $500 USDC (Notion: Scout fee - but usually $500 USDC)
  - (this line can be removed if there is no mitigation) Mitigation Review: XXX XXX USDC
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts XXX XXX XX 20:00 UTC (ex. `Starts March 22, 2023 20:00 UTC`)
- Ends XXX XXX XX 20:00 UTC (ex. `Ends March 30, 2023 20:00 UTC`)

**❗ Important notes for wardens** 
## 🐺 C4 staff: delete the PoC requirement section if not applicable - i.e. for non-Solidity/EVM audits.
1. A coded, runnable PoC is required for all High/Medium submissions to this audit. 
  - This repo includes a basic template to run the test suite.
  - PoCs must use the test suite provided in this repo.
  - Your submission will be marked as Insufficient if the POC is not runnable and working with the provided test suite.
  - Exception: PoC is optional (though recommended) for wardens with signal ≥ 0.68.
1. Judging phase risk adjustments (upgrades/downgrades):
  - High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
  - Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
  - As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.

## Automated Findings / Publicly Known Issues

The 4naly3er report can be found [here](https://github.com/code-423n4/YYYY-MM-contest-candidate/blob/main/4naly3er-report.md).

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._
## 🐺 C4: Begin Gist paste here (and delete this line)





# Scope

*See [scope.txt](https://github.com/code-423n4/2025-10-sequence/blob/main/scope.txt)*

### Files in scope


| File   | Logic Contracts | Interfaces | nSLOC | Purpose | Libraries used |
| ------ | --------------- | ---------- | ----- | -----   | ------------ |
| /src/Factory.sol | 1| **** | 14 | ||
| /src/Guest.sol | 1| **** | 49 | ||
| /src/Stage1Module.sol | 1| **** | 16 | ||
| /src/Stage2Module.sol | 1| **** | 14 | ||
| /src/Wallet.sol | 1| **** | 5 | ||
| /src/extensions/passkeys/Passkeys.sol | 1| **** | 71 | ||
| /src/extensions/recovery/Recovery.sol | 1| **** | 121 | ||
| /src/extensions/sessions/SessionErrors.sol | 1| **** | 23 | ||
| /src/extensions/sessions/SessionManager.sol | 1| **** | 92 | ||
| /src/extensions/sessions/SessionSig.sol | 1| **** | 237 | ||
| /src/extensions/sessions/explicit/ExplicitSessionManager.sol | 1| **** | 105 | ||
| /src/extensions/sessions/explicit/IExplicitSessionManager.sol | ****| 1 | 16 | ||
| /src/extensions/sessions/explicit/Permission.sol | 1| **** | 56 | ||
| /src/extensions/sessions/explicit/PermissionValidator.sol | 1| **** | 77 | ||
| /src/extensions/sessions/implicit/Attestation.sol | 1| **** | 61 | ||
| /src/extensions/sessions/implicit/ISignalsImplicitMode.sol | ****| 1 | 6 | ||
| /src/extensions/sessions/implicit/ImplicitSessionManager.sol | 1| **** | 46 | ||
| /src/modules/Calls.sol | 1| **** | 81 | ||
| /src/modules/ERC4337v07.sol | 1| **** | 41 | ||
| /src/modules/Hooks.sol | 1| **** | 61 | ||
| /src/modules/Implementation.sol | 1| **** | 25 | ||
| /src/modules/Nonce.sol | 1| **** | 25 | ||
| /src/modules/Payload.sol | 1| **** | 152 | ||
| /src/modules/ReentrancyGuard.sol | 1| **** | 17 | ||
| /src/modules/Storage.sol | 1| **** | 25 | ||
| /src/modules/auth/BaseAuth.sol | 1| **** | 85 | ||
| /src/modules/auth/BaseSig.sol | 1| **** | 283 | ||
| /src/modules/auth/SelfAuth.sol | 1| **** | 10 | ||
| /src/modules/auth/Stage1Auth.sol | 1| **** | 32 | ||
| /src/modules/auth/Stage2Auth.sol | 1| **** | 23 | ||
| /src/modules/interfaces/IAccount.sol | ****| 1 | 14 | ||
| /src/modules/interfaces/IAuth.sol | 1| **** | 3 | ||
| /src/modules/interfaces/ICheckpointer.sol | ****| 1 | 8 | ||
| /src/modules/interfaces/IDelegatedExtension.sol | ****| 1 | 3 | ||
| /src/modules/interfaces/IERC1155Receiver.sol | ****| 1 | 3 | ||
| /src/modules/interfaces/IERC1271.sol | ****| 2 | 6 | ||
| /src/modules/interfaces/IERC223Receiver.sol | ****| 1 | 3 | ||
| /src/modules/interfaces/IERC721Receiver.sol | ****| 1 | 3 | ||
| /src/modules/interfaces/IERC777Receiver.sol | ****| 1 | 3 | ||
| /src/modules/interfaces/IEntryPoint.sol | ****| 1 | 3 | ||
| /src/modules/interfaces/IPartialAuth.sol | ****| 1 | 4 | ||
| /src/modules/interfaces/ISapient.sol | ****| 2 | 5 | ||
| /src/utils/Base64.sol | 1| **** | 90 | ||
| /src/utils/LibBytes.sol | 1| **** | 90 | ||
| /src/utils/LibOptim.sol | 1| **** | 30 | ||
| /src/utils/P256.sol | 1| **** | 67 | ||
| /src/utils/WebAuthn.sol | 1| **** | 181 | ||
| **Totals** | **34** | **15** | **2385** | | |

### Files out of scope

*See [out_of_scope.txt](https://github.com/code-423n4/2025-10-sequence/blob/main/out_of_scope.txt)*

| File         |
| ------------ |
| ./script/Deploy.s.sol |
| ./script/DeployMocks.s.sol |
| ./src/Estimator.sol |
| ./src/Simulator.sol |
| ./test/Factory.t.sol |
| ./test/Guest.t.sol |
| ./test/Stage1Module.t.sol |
| ./test/Wallet.t.sol |
| ./test/extensions/passkeys/Passkeys.t.sol |
| ./test/extensions/recovery/Recovery.t.sol |
| ./test/extensions/sessions/Attestation.t.sol |
| ./test/extensions/sessions/Permission.t.sol |
| ./test/extensions/sessions/SessionCalls.t.sol |
| ./test/extensions/sessions/SessionManager.t.sol |
| ./test/extensions/sessions/SessionSig.t.sol |
| ./test/extensions/sessions/SessionTestBase.sol |
| ./test/extensions/sessions/explicit/ExplicitSessionManager.t.sol |
| ./test/extensions/sessions/explicit/PermissionValidator.t.sol |
| ./test/extensions/sessions/implicit/ImplicitSessionManager.t.sol |
| ./test/integrations/extensions/recovery/RecoveryDenialOfService.t.sol |
| ./test/integrations/extensions/sessions/ExtendedSessionTestBase.sol |
| ./test/integrations/extensions/sessions/SessionDenialOfService.t.sol |
| ./test/integrations/extensions/sessions/SessionLimitIncrementTest.t.sol |
| ./test/integrations/extensions/sessions/SessionSelfCall.t.sol |
| ./test/integrations/extensions/sessions/SessionSignatureAbuse.t.sol |
| ./test/integrations/extensions/sessions/SessionUsingERC4337.t.sol |
| ./test/integrations/extensions/sessions/SessionValueForwarding.t.sol |
| ./test/integrations/modules/ERC4337v07/ERC4337Entrypoint.t.sol |
| ./test/mocks/AcceptAll.sol |
| ./test/mocks/CanReenter.sol |
| ./test/mocks/Emitter.sol |
| ./test/mocks/MockERC20.sol |
| ./test/mocks/MockPayableReceiver.sol |
| ./test/mocks/ValueForwarder.sol |
| ./test/modules/BaseSig.t.sol |
| ./test/modules/Calls.t.sol |
| ./test/modules/ERC4337v07.t.sol |
| ./test/modules/Hooks.t.sol |
| ./test/modules/Implementation.t.sol |
| ./test/modules/Nonce.t.sol |
| ./test/modules/Payload.t.sol |
| ./test/utils/Base64.t.sol |
| ./test/utils/LibBytes.t.sol |
| ./test/utils/PrimitivesRPC.sol |
| ./test/utils/TestUtils.sol |
| Totals: 45 |

