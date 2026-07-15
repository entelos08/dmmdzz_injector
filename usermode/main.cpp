// =============================================================================
// usermode/main.cpp
//
// Controller for dmmdzz_injector. On startup (REPL mode) it auto-loads the
// driver via KDU (if not present) and auto-hides this process via DKOM.
// All patch commands target dmmdzz.exe (no process name argument needed).
//
// Usage:
//   <ctl>.exe                Interactive REPL (auto-load + auto-hide)
//   <ctl>.exe <command>      Run a single patch command
//
// Commands: antiacheat, freecard, cd, talent, zombie_thief, zombie_police, zombie, finaldead, weapon
//           and their restore* counterparts.
//
// REPL-only: hide, unhide, exit (auto-unhides)
//
// EDUCATIONAL: run as Administrator. The driver is auto-mapped via KDU.
// =============================================================================
#include "driver_ctl.hpp"
#include "driver_loader.hpp"
#include "process.hpp"

#include <windows.h>
#include <shellapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <iostream>

// Backup region size — we read/save/restore this many bytes so the restore
// can fully undo the patch even though only 5-6 bytes are modified.
// v4 weapon patch is 18 bytes inline, so we need at least 18 here.
static const size_t   PATCH_REGION     = 32;
// Read chunk size for scanning. METHOD_BUFFERED IOCTL limit is ~390KB,
// so 256KB per read is safe.
static const size_t   SCAN_CHUNK       = 0x40000;

// ---------------------------------------------------------------------------
// FreeCard patch targets — bypass ALL gold checks and deductions.
//
// The game has TWO separate currency systems:
//
//   1. Lobby currency (局外): 白金币/钻石/点券 — managed by GetCurrencyAmount.
//      Used for lobby upgrades, shop purchases outside of battle.
//
//   2. In-game battle gold (局内金币): EPropertyComp.m_Gold (uint at offset 0x3C).
//      Used for buying prop cards DURING battle. Flow:
//        CostGold() checks & deducts → SendReqSubGold() → server responds
//        → OnRpcSubCoin() → SubGold() updates m_Gold locally
//
// To make prop cards truly free in BOTH systems, we patch EIGHT methods:
//
//   Lobby (局外):
//     a) CanBuyCard / CanPlayerUseCard → return true (bypass pre-checks)
//     b) SubCoin → no-op (prevent local lobby-currency deduction)
//     c) RPCSubCoin handler (0x1F6B870) → no-op (prevent server lobby deduction)
//     d) GetCurrencyAmount → return 2,147,483,647 (always "rich" in lobby)
//
//   In-game (局内金币):
//     e) CostGold → return true (skip in-battle gold check + deduction)
//     f) OnRpcSubCoin (0x40D4BF0) → return true (skip server gold RPC sync)
//     g) get_IsCostFreeMode → return true (enable "免费模式" globally)
//
// RVAs are from the 32-bit dump.cs (IL2CPP x86, fastcall + caller cleanup).
// ---------------------------------------------------------------------------
struct FreeCardTarget {
    const char*   name;
    uintptr_t     rva;
    const uint8_t* patch;
    size_t        patchLen;
};

// Patch: mov eax,1; ret — makes bool methods return true (6 bytes)
static const uint8_t PATCH_RET_TRUE[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
// Patch: ret — makes void method a no-op (1 byte, caller cleans stack in fastcall)
static const uint8_t PATCH_RET_VOID[] = { 0xC3 };
// Patch: xor eax,eax; ret — returns bool false (3 bytes)
//   Same encoding as PATCH_RET_ZERO_FLOAT; defined separately for semantic clarity.
static const uint8_t PATCH_RET_FALSE[] = { 0x33, 0xC0, 0xC3 };
// Patch: mov eax,0x7FFFFFFF; xor edx,edx; ret — returns long 2147483647 (8 bytes)
//   For static long GetCurrencyAmount(Currency): ECX=arg, EDX=MethodInfo*
//   At return, EDX:EAX = 64-bit result. We return (long)2147483647.
static const uint8_t PATCH_RET_HUGE_MONEY[] = {
    0xB8, 0xFF, 0xFF, 0xFF, 0x7F,  // mov eax, 0x7FFFFFFF
    0x33, 0xD2,                     // xor edx, edx
    0xC3,                           // ret
};
// Patch: mov eax,0x270F; ret — returns int 9999 (6 bytes)
//   For int getters that return gold/coin amount.
static const uint8_t PATCH_RET_9999_INT[] = {
    0xB8, 0x0F, 0x27, 0x00, 0x00,  // mov eax, 0x270F (9999)
    0xC3,                           // ret
};
// Patch: mov eax,0x270F; xor edx,edx; ret — returns long 9999 (8 bytes)
//   For static long GetCurrencyAmount: EDX:EAX = 64-bit result.
static const uint8_t PATCH_RET_9999_LONG[] = {
    0xB8, 0x0F, 0x27, 0x00, 0x00,  // mov eax, 0x270F (9999)
    0x33, 0xD2,                     // xor edx, edx
    0xC3,                           // ret
};
// Patch: safe coin fix — tries [esp+4] as this (cdecl), validates pointer, writes 9999 (22 bytes)
//   For InGameStore.OnCoinChanged(bool): CRASH FIX.
//   Previous version used ECX as this, but OnCoinChanged is NOT thiscall —
//   ECX contains a non-pointer value (0x7d=125), causing INVALID_POINTER_WRITE
//   crash at [ecx+98h]=[0x115]. This version reads this from [esp+4] (cdecl
//   convention where this is passed on stack), validates it's a real pointer
//   (>0x10000), then writes m_CoinNum @0x98 = 9999. If [esp+4] is not a valid
//   pointer, it safely skips the write and returns (no crash).
static const uint8_t PATCH_FIX_COIN_9999[] = {
    0x8B, 0x44, 0x24, 0x04,               // mov eax, [esp+4]  — this from stack (cdecl)
    0x3D, 0x00, 0x00, 0x01, 0x00,         // cmp eax, 0x10000  — valid pointer check
    0x72, 0x0A,                             // jb skip (+10 bytes, past the mov)
    0xC7, 0x80, 0x98, 0x00, 0x00, 0x00,   // mov dword ptr [eax+0x98], imm32
    0x0F, 0x27, 0x00, 0x00,               // imm32 = 0x0000270F (9999)
    0xC3,                                   // skip: ret
};

// Patch: jmp short 0x11 — bypass dword_16097728 singleton block in OnButtonUp Path 2.
//   OnButtonUp at RVA 0x286C5FF has "jz short loc_1286C612" (74 11). When the
//   dword_16097728 singleton has flag [0x2F]&0x20 set, the jz is NOT taken and
//   the method exits with bl=false (blocking RPC). Changing 74→EB makes it
//   unconditionally continue to loc_1286C612, skipping the block.
static const uint8_t PATCH_BYPASS_INPUT_LOCK[] = { 0xEB, 0x11 };

// Patch: nop nop — bypass LocalNum/isLocalPlayer check in OnButtonUp Path 2.
//   At RVA 0x286C695, "jz short loc_1286C6CC" (74 35) skips RPC when the player
//   is not the local 0-slot player (PlayerController.LocalNum != 0, field_0x340).
//   NOP-ing this jz forces the RPC path to continue regardless of player slot.
static const uint8_t PATCH_BYPASS_LOCALNUM_CHECK[] = { 0x90, 0x90 };

// ---------------------------------------------------------------------------
// Prop card release RPC flow — three key methods (all CLIENT-side, NOT server-
// authoritative):
//
// 1. OnButtonUp(bool tryCancel) — RVA 0x286C530 (qntQLIdk class, dump.cs:126741)
//    Entry point for prop card release. Has two RPC sending paths:
//      Path 1 (StopPreview==true → loc_1286C6D3): gated by sub_1284F490 which
//            returns qntQLIdk.field_0x38 (PlayerController). If null → no RPC.
//            Then calls vNolvNIB to send the actual RPC.
//      Path 2 (StopPreview==false → loc_1286C5F6): gated by three checks:
//            a) dword_16097728 singleton block (RVA 0x286C5FF jz) — if active,
//               exits with false, no RPC.
//            b) dword_160F26F4 virtual call OR PlayerController.LocalNum==0
//               (field_0x340) — non-local player → no RPC.
//            c) YzCvqpay() — CardType must be Custom(0) or Placeable(2),
//               else no RPC.
//
// 2. YzCvqpayczgbhkaouydbFdUFBBLBkuCotkBjRpGo() — RVA 0x286D820 (dump.cs:126717)
//    Private bool getter on qntQLIdk. Reads this.field_0x24 (CardLogicConfig)
//    then checks field_0x14 (m_CardType):
//      CardType.Custom(0)    → return true  (allow RPC)
//      CardType.Placeable(2) → return true  (allow RPC)
//      Buff(1)/ShapeShift(3)/Skill(4) → return false (block RPC)
//    Patching this to always return true allows ALL card types to send RPC.
//
// 3. vNolvNIBahZUEylkyelkFSZuKqYSkHSfkHmvRbTy(V3,V3,V3,CachedBuf<int>)
//    — RVA 0x2870500 (dump.cs:126618)
//    The actual RPC sender. Stores position/direction/targetIDs into qntQLIdk
//    fields (0x4C/0x58/0x64), then calls DHbCLXjKbCtxECVYrJIetYrEHRrwQtAMYBQtnlst
//    (RVA 0x286B6A0) which dispatches to SbYiUayW wrapper (RVA 0x2663940) →
//    wfRGmujt [DmmRPC(10004)] (RVA 0x2667210) — the real server broadcast.
//    vNolvNIB has a switch on CardType (0-3) to select the send path.
// ---------------------------------------------------------------------------

static const FreeCardTarget FREECARD_TARGETS[] = {
    // --- Lobby currency + client pre-checks (局外) ---
    { "CardUtility.CanBuyCard(int)",                          0x2A8D350, PATCH_RET_TRUE,      sizeof(PATCH_RET_TRUE) },
    { "CardUtility.CanPlayerUseCard(PlayerController,int)",   0x2A8D790, PATCH_RET_TRUE,      sizeof(PATCH_RET_TRUE) },
    { "PlayerController.SubCoin(int,int,int) — no local deduct", 0x1EB6A20, PATCH_RET_VOID,   sizeof(PATCH_RET_VOID) },
    { "RPCSubCoin handler — no server deduct",                0x1F6B870, PATCH_RET_VOID,      sizeof(PATCH_RET_VOID) },
    // --- Fix lobby currency to 9999 (欺骗客户端大厅有9999金币) ---
    // GetCurrencyAmount(Currency) is static long: EDX:EAX = 64-bit result.
    { "GetCurrencyAmount(Currency) — fix gold to 9999",       0x8583D0,  PATCH_RET_9999_LONG, sizeof(PATCH_RET_9999_LONG) },
    // --- In-game battle gold (局内金币) ---
    // CostGold: the actual in-game gold check+deduction method. Returning true
    // makes it skip the gold check entirely (prop cards cost nothing in-battle).
    { "CostGold — skip in-game gold check/deduction",         0x40FA820, PATCH_RET_TRUE,      sizeof(PATCH_RET_TRUE) },
    // OnRpcSubCoin: server RPC handler for in-game gold sync. Returning true
    // prevents the server from pushing gold deductions to the client.
    { "OnRpcSubCoin(battle) — skip server gold RPC",          0x40D4BF0, PATCH_RET_TRUE,      sizeof(PATCH_RET_TRUE) },
    //{ "IsCostFreeMode — enable free cost mode",               0x7DF1A0,  PATCH_RET_TRUE,      sizeof(PATCH_RET_TRUE) },
    // --- Fix in-game coin to 9999 (劫持RPC同步,固定m_CoinNum=9999) ---
    // InGameStore.OnCoinChanged(bool) is called when server pushes coin updates.
    // Patch its entry to `mov [ecx+98h], 9999; ret` — forces m_CoinNum to 9999
    // on every sync, making the client believe it has 9999 coins.
    // This bypasses gold checks that read m_CoinNum directly (not via getters).
    // StopPreview removed: 998 error + previously verified ineffective.
    { "InGameStore.OnCoinChanged(bool) — fix coin to 9999",   0x256F8F0, PATCH_FIX_COIN_9999, sizeof(PATCH_FIX_COIN_9999) },
    // --- Prop card RPC broadcast (局内道具卡广播) ---
    // Problem: UI allows releasing prop cards, but no RPC is broadcast (not even
    // in own view). Root cause: OnButtonUp Path 2 has three client-side gates that
    // block the RPC send. These patches bypass all three gates so the RPC reaches
    // vNolvNIB → wfRGmujt [DmmRPC(10004)] for server broadcast.
    //
    // Gate 1: dword_16097728 singleton block (OnButtonUp RVA 0x286C5FF)
    //   "jz short loc_1286C612" (74 11) → "jmp short" (EB 11). When this singleton
    //   is active, the original code calls a virtual method then exits with false
    //   (no RPC). Forcing the jump skips the block entirely.
    { "OnButtonUp — bypass input-lock singleton",              0x286C5FF, PATCH_BYPASS_INPUT_LOCK, sizeof(PATCH_BYPASS_INPUT_LOCK) },
    //
    // Gate 2: LocalNum/isLocalPlayer check (OnButtonUp RVA 0x286C695)
    //   "jz short loc_1286C6CC" (74 35) → "nop nop" (90 90). The original code
    //   skips RPC when PlayerController.LocalNum != 0 (non-local player slot).
    //   NOP-ing the jz allows RPC from any player slot.
    { "OnButtonUp — bypass LocalNum check",                    0x286C695, PATCH_BYPASS_LOCALNUM_CHECK, sizeof(PATCH_BYPASS_LOCALNUM_CHECK) },
    //
    // Gate 3: YzCvqpay card-type filter (RVA 0x286D820)
    //   Returns true only for CardType.Custom(0) or Placeable(2). Buff(1),
    //   ShapeShift(3), Skill(4) cards are blocked. Patching to "mov eax,1; ret"
    //   forces true for all card types.
    { "YzCvqpay — allow all card types to broadcast",          0x286D820, PATCH_RET_TRUE,      sizeof(PATCH_RET_TRUE) },
};
static const size_t FREECARD_TARGET_COUNT = sizeof(FREECARD_TARGETS) / sizeof(FREECARD_TARGETS[0]);
static const char*  FREECARD_BACKUP       = "dmmdzz_freecard_backup.bin";

// ---------------------------------------------------------------------------
// Anti-cheat disable targets — neutralize all cheat-detection functions.
//
// After patching m_CoinNum / gold checks, the game's anti-cheat system may
// detect tampering via Enc* wrappers or server RPC pushes. These patches
// neutralize 18 detection/reporting functions:
//
//   a) IsCheat(Enc*) x5 — encrypted-value tamper detection → return false
//   b) get_IsUseAntiCheatSys — anti-cheat system toggle → return false
//   c) NotifyCheating — server RPC(1018) cheat notification → no-op
//   d) OnProtectCallback x2 — SDK protection callback → no-op
//   e) OnSyncList(RpcCheatBlacklist) x2 — blacklist sync (base+override) → no-op
//   f) IODZRBzo(RpcNotifyCheating) x2 — cheat-notify event handlers → no-op
//   g) SendGetCheatBlacklist — request blacklist from server → no-op
//   h) CheckCheatList / ProtectProcess / ProcessDetect / ExitProcessDetect
//      — process-level cheat detection → no-op
// ---------------------------------------------------------------------------
static const FreeCardTarget ANTI_CHEAT_TARGETS[] = {
    // --- IsCheat: encrypted-value tamper detection (5 overloads) → false ---
    { "IsCheat(EncInt) — no tamper",                0x2DBACA0, PATCH_RET_FALSE, sizeof(PATCH_RET_FALSE) },
    { "IsCheat(EncBool) — no tamper",               0x2DBAC60, PATCH_RET_FALSE, sizeof(PATCH_RET_FALSE) },
    { "IsCheat(EncFloat) — no tamper",              0x2DBACE0, PATCH_RET_FALSE, sizeof(PATCH_RET_FALSE) },
    { "IsCheat(EncLong) — no tamper",               0x2DBAC20, PATCH_RET_FALSE, sizeof(PATCH_RET_FALSE) },
    { "IsCheat(EncString) — no tamper",             0x2DBAD20, PATCH_RET_FALSE, sizeof(PATCH_RET_FALSE) },
    // --- Anti-cheat system toggle → false (disabled) ---
    { "get_IsUseAntiCheatSys — disable",            0x2E4C7E0, PATCH_RET_FALSE, sizeof(PATCH_RET_FALSE) },
    // --- Server cheat notification RPC → no-op ---
    { "NotifyCheating(int,string) — ignore RPC",    0x28A4400, PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    // --- Protection callbacks → no-op ---
    { "OnProtectCallback(bool,string) — no-op",     0x2B422C0, PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    { "OnProtectCallback(int,string) — no-op",      0x2B42310, PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    // --- Cheat blacklist sync (base + override) → no-op ---
    { "OnSyncList(RpcCheatBlacklist) base — no-op", 0xB89080,  PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    { "OnSyncList(RpcCheatBlacklist) over — no-op", 0x2B42EE0, PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    // --- Cheat-notify event handlers → no-op ---
    { "IODZRBzo(RpcNotifyCheating) — no-op",        0xB88B80,  PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    { "IODZRBzo(LMNEvent_RPCNotifyCheating) — no-op", 0x1F6F360, PATCH_RET_VOID, sizeof(PATCH_RET_VOID) },
    // --- Blacklist request → no-op ---
    { "SendGetCheatBlacklist — no-op",              0xB89CB0,  PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    // --- Process-level detection → no-op ---
    { "CheckCheatList — no-op",                     0x6511F0,  PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    { "ProtectProcess — no-op",                     0x651760,  PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    { "ProcessDetect — no-op",                      0x4AF1170, PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
    { "ExitProcessDetect — no-op",                  0x4AEBC00, PATCH_RET_VOID,  sizeof(PATCH_RET_VOID) },
};
static const size_t ANTI_CHEAT_TARGET_COUNT = sizeof(ANTI_CHEAT_TARGETS) / sizeof(ANTI_CHEAT_TARGETS[0]);
static const char*  ANTI_CHEAT_BACKUP       = "dmmdzz_antiacheat_backup.bin";

// ---------------------------------------------------------------------------
// Cooldown patch targets — set prop card cooldown to minimum (0).
//
// CRITICAL ROOT CAUSE: InGameStoreInfo properties are VIRTUAL. At runtime,
// InGameStoreInfo instances are actually InGameStoreInfoObjectSegment<T>
// (ZeroFormatter serialized objects). Virtual dispatch goes to the ObjectSegment
// overrides, NOT the base class methods. Patching the base class get_Cooldown()
// (RVA 0x716990) had NO EFFECT because it was never called at runtime.
//
// The fix: patch the ObjectSegment override methods instead. There are two
// generic instantiations (<object> and <__Il2CppFullySharedGenericType>); both
// are patched to cover all virtual dispatch paths.
//
// Targets (18 total):
//   --- InGameStoreInfoObjectSegment overrides (the REAL runtime getters) ---
//   a) ObjectSegment<object>.get_Cooldown              RVA 0x33570E0 → 0.0f
//   b) ObjectSegment<object>.get_CooldownOnEnd         RVA 0x3357090 → 0.0f
//   c) ObjectSegment<object>.get_WaitTriggerTime       RVA 0x3357E70 → 0.0f
//   d) ObjectSegment<__Shared>.get_Cooldown            RVA 0x3357130 → 0.0f
//   e) ObjectSegment<__Shared>.get_CooldownOnEnd       RVA 0x3357000 → 0.0f
//   f) ObjectSegment<__Shared>.get_WaitTriggerTime     RVA 0x3357EC0 → 0.0f
//   --- Base class fallback (in case of non-serialized instances) ---
//   g) InGameStoreInfo.get_Cooldown (base)             RVA 0x716990  → 0.0f
//   h) InGameStoreInfo.get_CooldownOnEnd (base)        RVA 0x726280  → 0.0f
//   --- CD discount (both implementations) ---
//   i)  EPropertyComp.GetPropCardCdDiscount            RVA 0x40CCAA0 → 1.0f
//   j)  PlayerController.GetPropCardCdDiscount         RVA 0x1EAA4B0 → 1.0f
//   --- Runtime CD gate (UI-level cooldown enforcement) ---
//   k) InGameInteractionButton.CheckIsCoolDown()       RVA 0x23D5100 → false
//   l) InGameInteractionButton.GetPropCooldownTime()   RVA 0x23D6460 → 0.0f
//   --- InGameStore-level CD enforcement (STORE-WIDE cooldown) ---
//   The InGameStore class tracks a global m_CooldownTime (0x3C) and a per-card
//   SafeGameDictionary<int,float> (0xAC) that enforce a CD SEPARATE from the
//   per-card InGameStoreInfo.get_Cooldown(). This is why SOME prop cards still
//   had CD after the above patches — the store-level gate was never bypassed.
//   m) InGameStore.GetCardCdRemain(InGameStoreInfo)    RVA 0x256EE80 → 0.0f
//   n) InGameStore.GetCardCdRemainById(int)            RVA 0x25799C0 → 0.0f
//   o) InGameStore.IsInCoolDown()                      RVA 0x2579690 → false
//   p) InGameStore.SetCardCd(int,float)                RVA 0x25765F0 → no-op
//   q) InGameStore.SetCardCdEx(int,float,bool,int)     RVA 0x2576700 → no-op
//   r) InGameStore.SetCardCdPublic(int,float)          RVA 0x2570900 → no-op
//
// WaitTriggerTime: the delay before a card can trigger after purchase. Setting
// to 0 allows immediate triggering. Previously UNPATCHED — a likely cause of
// the "cd has no effect" issue alongside the ObjectSegment virtual dispatch.
//
// NOTE: CheckTrigger (talent 100% trigger) has been moved to the separate
// 'talent' subcommand. Run 'talent' before 'cd' to make the free-purchase
// talent fire and bypass server gold checks.
//
// Float return in IL2CPP x86: value is in EAX as IEEE-754 bit pattern.
//   0.0f = 0x00000000 → xor eax,eax; ret  (3 bytes)
//   1.0f = 0x3F800000 → mov eax,0x3F800000; ret  (6 bytes)
// Bool false in IL2CPP x86: EAX = 0, same encoding as 0.0f.
// ---------------------------------------------------------------------------
// Patch: xor eax,eax; ret — returns float 0.0f / bool false (3 bytes)
static const uint8_t PATCH_RET_ZERO_FLOAT[] = { 0x33, 0xC0, 0xC3 };
// Patch: mov eax,0x3F800000; ret — returns float 1.0f (6 bytes)
static const uint8_t PATCH_RET_ONE_FLOAT[] = {
    0xB8, 0x00, 0x00, 0x80, 0x3F,  // mov eax, 0x3F800000
    0xC3,                           // ret
};
// Patch: mov eax,0x40A00000; ret — returns float 5.0f (6 bytes)
//   Used to override get_MoveSpeed() so the player moves at full speed
//   even when the game thinks they are downed/dying.
static const uint8_t PATCH_RET_FLOAT_5[] = {
    0xB8, 0x00, 0x00, 0xA0, 0x40,  // mov eax, 0x40A00000
    0xC3,                           // ret
};
// Patch: mov eax,0x3DCCCCCD; ret — returns float 0.1f (6 bytes)
//   Used for SkillStackConfig.get_Cd() to make charge time very short.
static const uint8_t PATCH_RET_FLOAT_01[] = {
    0xB8, 0xCD, 0xCC, 0xCC, 0x3D,  // mov eax, 0x3DCCCCCD
    0xC3,                           // ret
};

static const FreeCardTarget CD_TARGETS[] = {
    // --- ObjectSegment<object> overrides (the ACTUAL runtime getters) ---
    { "ObjSeg<object>.get_Cooldown — runtime CD = 0",          0x33570E0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "ObjSeg<object>.get_CooldownOnEnd — runtime end CD = 0", 0x3357090, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "ObjSeg<object>.get_WaitTriggerTime — trigger delay = 0", 0x3357E70, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    // --- ObjectSegment<__Il2CppFullySharedGenericType> overrides (shared generic path) ---
    { "ObjSeg<__Shared>.get_Cooldown — shared CD = 0",         0x3357130, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "ObjSeg<__Shared>.get_CooldownOnEnd — shared end CD = 0", 0x3357000, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "ObjSeg<__Shared>.get_WaitTriggerTime — shared delay = 0", 0x3357EC0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    // --- Base class fallback (non-serialized InGameStoreInfo instances) ---
    { "InGameStoreInfo.get_Cooldown (base) — fallback CD = 0",   0x716990,  PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "InGameStoreInfo.get_CooldownOnEnd (base) — fallback = 0", 0x726280,  PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    // --- CD discount (both implementations) ---
    { "EPropertyComp.GetPropCardCdDiscount — 100% discount",     0x40CCAA0, PATCH_RET_ONE_FLOAT,  sizeof(PATCH_RET_ONE_FLOAT) },
    { "PlayerController.GetPropCardCdDiscount — 100% discount",  0x1EAA4B0, PATCH_RET_ONE_FLOAT,  sizeof(PATCH_RET_ONE_FLOAT) },
    // --- Runtime CD gate (UI-level cooldown enforcement) ---
    { "InGameInteractionButton.CheckIsCoolDown — bypass gate",   0x23D5100, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "InGameInteractionButton.GetPropCooldownTime — CD = 0",    0x23D6460, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    // --- InGameStore-level CD enforcement (STORE-WIDE cooldown gate) ---
    // These methods track/enforce a CD SEPARATE from InGameStoreInfo.get_Cooldown.
    // The store keeps m_CooldownTime (0x3C) and a per-card SafeDictionary (0xAC).
    // Without patching these, some prop cards still enforce a CD after use.
    // Getters → return 0.0f (no remaining CD); setters → no-op (never set CD).
    { "InGameStore.GetCardCdRemain(StoreInfo) — CD remain = 0",  0x256EE80, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "InGameStore.GetCardCdRemainById(int) — CD remain = 0",    0x25799C0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "InGameStore.IsInCoolDown() — not in cooldown",            0x2579690, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "InGameStore.SetCardCd(int,float) — block CD set",         0x25765F0, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    { "InGameStore.SetCardCdEx(int,float,bool,int) — block set", 0x2576700, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    { "InGameStore.SetCardCdPublic(int,float) — block CD set",   0x2570900, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
};
static const size_t CD_TARGET_COUNT = sizeof(CD_TARGETS) / sizeof(CD_TARGETS[0]);
static const char*  CD_BACKUP       = "dmmdzz_cd_backup.bin";

// ---------------------------------------------------------------------------
// Talent patch targets — make the "free purchase" / SelfHelpDevil talent
// trigger 100%.
//
// When a player is downed, the game rolls a talent check (CheckTrigger).
// If it succeeds, the "free purchase" talent fires, which:
//   1. Sends LMNEvent_RPCSelfHelp to the server
//   2. Server authenticates and broadcasts the SelfHelp event
//   3. Client receives it, calls AddCoin(reason=SelfHelpDevil=55)
//   4. Server-authenticated gold is added to the player
//
// Patching CheckTrigger → true makes this fire every time the player is
// downed, bypassing the server's gold check for prop card purchases.
//
// This also fixes the "CD only works once" issue: the server blocks
// subsequent prop card purchases when gold is insufficient, but the
// 100% talent trigger forces the free-purchase path.
// ---------------------------------------------------------------------------
static const FreeCardTarget TALENT_TARGETS[] = {
    { "CheckTrigger(Talent,float) — 100% talent trigger",   0x7C49D0,  PATCH_RET_TRUE,       sizeof(PATCH_RET_TRUE) },
};
static const size_t TALENT_TARGET_COUNT = sizeof(TALENT_TARGETS) / sizeof(TALENT_TARGETS[0]);
static const char*  TALENT_BACKUP       = "dmmdzz_talent_backup.bin";

// ---------------------------------------------------------------------------
// Skill CD targets — remove active skill cooldown.
//
// ROOT CAUSE ANALYSIS (why previous attempts failed):
//
// 1. THREE CD tracker classes, not one! All inherit from
//    JyxYuuQRGBArkkElpVHljjWbZFjaVVnCDplCiiuL:
//    - SkillCD (TypeDefIndex 16483) — standard CD tracker
//    - gcPUCgbPHQSEEyBkdcFBzdyFZBwbbQVoKGEVtKQE (16484) — variant CD tracker
//    - vfUKKvIAiffjehhftEMjkUyBBkmeZUUYVbbUnsqY (16487) — charge/stack CD tracker
//    The SkillComp class (gzoaaBdSoOXdIiiScZIQKoSRRvXJSFMXmZZJGTmu) holds
//    instances of ALL THREE and uses them polymorphically via the base class
//    reference.  Previous patch only covered SkillCD → skills using the other
//    two trackers were still blocked.
//
// 2. Patching state management methods (Update, OnUseSkill, get_IsInProgress,
//    get_Progress, get_TotalTime) BREAKS the CD state machine.  After the
//    first skill use, the internal state gets stuck and the skill can NEVER
//    fire again — even after the real CD expires.
//
// CORRECT APPROACH: Patch ONLY the getter methods that are used for CHECKS.
// Let the state machine (Update, OnUseSkill, Reset) run normally.  The CD
// timer starts and ticks down as usual, but the check methods always return
// "ready" / "0 remaining", so the skill can be used again immediately.
//
//   - get_IsReady() → true (always ready, for ALL 3 tracker classes)
//   - get_RemainTime() → 0 (UI shows 0 remaining, for classes that have it)
//   - RoleSkill.get_RemainedTime() → 0 (legacy CD getter)
//   - RoleSkill.get_Cooldown() → 0 (legacy CD value)
//   - SkillStackConfig.get_Cd() → 0.1f (charge time = 0.1s for charge skills)
// ---------------------------------------------------------------------------
static const FreeCardTarget SKILLCD_TARGETS[] = {
    // --- CD tracker class 1: SkillCD (standard) ---
    { "SkillCD.get_IsReady — always ready",                    0x1F4EFE0, PATCH_RET_TRUE,       sizeof(PATCH_RET_TRUE) },
 //   { "SkillCD.get_RemainTime — remaining CD = 0",              0x1CECEF0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    // --- CD tracker class 2: gcPUCgbPHQSEEyBkdcFBzdyFZBwbbQVoKGEVtKQE (variant) ---
 //   { "gcPUCg.get_IsReady — always ready",                     0x1F52490, PATCH_RET_TRUE,       sizeof(PATCH_RET_TRUE) },
 //   { "gcPUCg.get_RemainTime — remaining CD = 0",              0x1F52760, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    // --- CD tracker class 3: vfUKKvIAiffjehhftEMjkUyBBkmeZUUYVbbUnsqY (charge/stack) ---
   // { "vfUKKv.get_IsReady — always ready",                     0x1F5E900, PATCH_RET_TRUE,       sizeof(PATCH_RET_TRUE) },
    // --- RoleSkill class (legacy CD getters, shared by all 10 subclasses) ---
    { "RoleSkill.get_Cooldown — cooldown = 0",                 0x26753C0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
  //  { "RoleSkill.get_RemainedTime — remained = 0",             0x2675C20, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    // --- Charge/stack skill: make charge time 0.1s (instant recharge) ---
    { "SkillStackConfig.get_Cd — charge time = 0.1s",          0x2E2B220, PATCH_RET_FLOAT_01,   sizeof(PATCH_RET_FLOAT_01) },
};
static const size_t SKILLCD_TARGET_COUNT = sizeof(SKILLCD_TARGETS) / sizeof(SKILLCD_TARGETS[0]);
static const char*  SKILLCD_BACKUP       = "dmmdzz_skillcd_backup.bin";

// ---------------------------------------------------------------------------
// Zombie patch targets — keep acting after HP reaches 0.
//
// ROOT CAUSE ANALYSIS (why the first attempt failed):
//
// 1. STATE GETTERS: IL2CPP emits non-virtual get_IsDying/get_FinalDead per
//    concrete class.  The runtime object is a subclass (Gphz=police /
//    dQhho=thief), so the subclass method is what actually gets called.
//    Patching only the base-class virtual methods is NOT enough.
//
// 2. MOVE SPEED: dQhho (thief) has its own get_MoveSpeed() and
//    UpdateMoveSpeed().  When the player is downed, UpdateMoveSpeed() lowers
//    the speed and get_MoveSpeed() returns the reduced value.  Patching
//    get_IsDying→false alone does NOT restore speed because the speed field
//    was already overwritten by UpdateMoveSpeed().  We must patch
//    get_MoveSpeed() to return a fixed high value AND make UpdateMoveSpeed()
//    a no-op so the speed field is never lowered.
//
// 3. CAN MOVE: dQhho.CanMove() is a private method that gates movement.
//    Returning true ensures the player can always move.
//
// 4. FINAL DEAD: FinalDead is set locally via set_FinalDead() when
//    dyingTime exceeds finalDeadTime[] — NOT via RPC.  We block both the
//    setter and LocalFinalDead() to prevent the dying→finaldead transition.
//
// 5. PROP CARDS: TryUsePropCard(has ignoreDying param) internally calls
//    get_IsDying().  With get_IsDying() patched→false, the check passes.
//
// SPLIT: Targets are split into COMMON (shared base-class + Gphz) + THIEF
// (dQhho-specific) + POLICE (Gphz-specific).  This allows applying only the
// relevant patches depending on which role the player is playing.
//
// EncBool is a 2-byte struct {m_RawValue, m_EncKey}; returning 0 in EAX gives
// EncBool(0,0) → decrypted 0^0 = 0 = false.  Safe for xor eax,eax; ret.
//
// RVAs from the 32-bit IL2CPP x86 dump (fastcall, caller stack cleanup).
// ---------------------------------------------------------------------------

// --- COMMON targets: base PlayerController + Gphz (police base) ---
// Applied for BOTH thief and police.  dQhho inherits from Gphz, so the
// Gphz setters/LocalFinalDead affect thief runtime objects too.
//
// CRITICAL: In addition to the non-virtual get_IsDying()/get_IsDead(),
// PlayerController has VIRTUAL state properties (Slot 84/86/90/94/96) with
// obfuscated names.  These are dispatched via the vtable when accessed through
// a base-class reference — the non-virtual getters are NOT called in that case.
// We must patch BOTH the non-virtual getters AND the virtual slot getters.
//
// Also critical: get_IsInteractable() (non-virtual, 0x1EC2490) gates prop-card
// usage.  When the player is downed, IsInteractable returns false, blocking
// all card interactions.  Patching it →true is the key fix for prop cards.
static const FreeCardTarget ZOMBIE_COMMON_TARGETS[] = {
    // --- Previous 24 getter/buff/RPC targets commented out (ineffective) ---
    // Root cause: IL2CPP inlines simple getters, so patching their entry points
    // has no effect. The real fix is OnReSyncRead below.
    { "get_IsInteractable() — always true (enable prop cards)", 0x1EC2490, PATCH_RET_TRUE,      sizeof(PATCH_RET_TRUE) },

    { "Slot86 virtual EncBool (vIsDying) base → false",         0x1EC4860, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "Slot84 virtual bool (vState1) base → false",             0x1EC4BE0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "Slot90 virtual bool (vState2) base → false",             0x1EC6550, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "Slot94 virtual bool (vState3) base → false",             0x1EC4F30, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
     
    { "Slot96 virtual EncBool (vIsDead) base → false",          0x1EC6760, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "Gphz.Slot96 override (vIsDead) → false",                 0x25F9D70, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    
    { "Gphz.get_IsDying() (EncBool=false)",                     0x2605940, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
   // { "Gphz.get_FinalDead() (bool=false)",                      0x26057F0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
   // { "Gphz.set_FinalDead() — block local finaldead set",       0x2606770, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
   // { "Gphz.LocalFinalDead() — block local finaldead trigger",  0x2603F00, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    { "OnFinalDead(RPC) — block server final death",            0x1F70870, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    { "BuffMod_MovementModify.OnStart — block dying speed debuff", 0x24ACB70, PATCH_RET_VOID,     sizeof(PATCH_RET_VOID) },

    // === THE NUCLEAR OPTION: OnReSyncRead ===
    // The server pushes player state (IsDying, IsFinalDead, HP, etc.) to the
    // client via OnReSyncRead(). Patching → no-op makes the client IGNORE all
    // server state pushes, so it never enters the dying state.
    //{ "PlayerController.OnReSyncRead — block server state sync",  0x1EAEE20, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    //{ "Gphz.OnReSyncRead — block server state sync (thief path)", 0x24D2160, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    // === THE REAL CAUSE OF REAL-PLAYER DAMAGE: DmmRPC ===
    // Real-player attacks bypass OnReSyncRead and use DmmRPC(1005) instead.
    // This RPC carries (float damage, int attackerId, ..., DamageExtraInfo).
    // Patching it → no-op makes the client IGNORE all incoming damage from
    // other players. Combined with OnReSyncRead patch above, this blocks BOTH
    // AI/trap damage (OnReSyncRead path) AND real-player damage (DmmRPC path).
    //
    // Class: JVKdHHkKzLlsKdiNWwqHOBLXDPBXwwOBoAfWBXZH (TypeDefIndex 187)
    // — a MonoBehaviour network handler attached to every PlayerController.
    { "DmmRPC(1005) — block real-player attack damage",           0x25F7F00, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    // DmmRPC(1004): batch attribute update (int[], float[], float[], bool).
    // Server pushes HP/speed/attribute arrays. Patching → no-op prevents
    // server from overwriting local HP via batch sync.
   { "DmmRPC(1004) — block batch attribute/HP sync",             0x25F9010, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
};

// --- THIEF-specific targets: dQhho class (inherits from Gphz) ---
static const FreeCardTarget ZOMBIE_THIEF_TARGETS[] = {
    { "dQhho.get_IsDying() (bool=false)",                       0x2132360, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    // Move speed: return 5.0f so the player moves at full speed even when downed
    { "dQhho.get_MoveSpeed() — always return 5.0f",             0x2132630, PATCH_RET_FLOAT_5,     sizeof(PATCH_RET_FLOAT_5) },
    // CanMove: always return true so movement is never blocked
    { "dQhho.CanMove() — always true",                          0x2106B90, PATCH_RET_TRUE,        sizeof(PATCH_RET_TRUE) },
    // UpdateMoveSpeed: no-op so the speed field is never lowered by dying logic
    { "dQhho.UpdateMoveSpeed() — no-op (prevent speed lower)",  0x210D200, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    // === THE KEY FOR PROP CARDS: get_Interactive() ===
    // dQhho.get_Interactive() returns false when downed, blocking ALL card
    // interactions at the UI level. This is separate from get_IsInteractable()
    // (base PlayerController). Patching both ensures prop cards work regardless
    // of which check path the UI uses.
    { "dQhho.get_Interactive() — always true (prop cards)",     0x2132200, PATCH_RET_TRUE,        sizeof(PATCH_RET_TRUE) },
};

// --- POLICE-specific targets: Gphz class ---
// Note: Gphz does not have its own get_MoveSpeed/CanMove — these are handled
// by the base PlayerController or a movement behaviour component.  The common
// targets (state getters + setters) should be sufficient to restore normal
// movement for police.  If police speed is still reduced, we may need to
// find and patch the police movement component separately.
//
// Currently empty — CmdZombiePolice applies ONLY ZOMBIE_COMMON_TARGETS.
// When police-specific targets are found, add them here and switch
// CmdZombiePolice to use ApplyMergedPatches.

static const char*  ZOMBIE_THIEF_BACKUP  = "dmmdzz_zombie_thief_backup.bin";
static const char*  ZOMBIE_POLICE_BACKUP = "dmmdzz_zombie_police_backup.bin";
// Legacy: combined backup (all targets at once)
static const char*  ZOMBIE_BACKUP        = "dmmdzz_zombie_backup.bin";

// ---------------------------------------------------------------------------
// FinalDead patch targets — block the transition from Dying to FinalDead.
//
// When a player is downed (Dying), a timer counts down. When it expires,
// the player transitions to FinalDead (permanent death, can no longer be
// revived). These patches block that transition at three points:
//
//   a) Gphz.set_FinalDead(bool)  — the local setter that writes the field
//   b) Gphz.LocalFinalDead()     — the local trigger that calls set_FinalDead
//   c) OnFinalDead (RPC)         — the server RPC that forces FinalDead remotely
//
// This is separate from the "zombie" patch (which ignores the Dying state
// entirely). Use this when you want to stay in Dying state indefinitely
// without progressing to FinalDead.
// ---------------------------------------------------------------------------
static const FreeCardTarget FINALDEAD_TARGETS[] = {
     //   { "get_IsDying() base (EncBool=false)",                     0x1EC23D0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
//    { "get_IsDead() base virtual (Slot 102) — never dead",      0x13745C0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
//    { "get_IsDead() subclass override (Slot 102) — never dead", 0x229D790, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
//    { "get_FinalDead() base virtual (Slot 92) — never dead",    0x1EC1990, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
//    { "get_FinalDead() override #1 (Slot 92) — never dead",     0x229FC10, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
 //   { "get_FinalDead() override #2 (Slot 92) — never dead",     0x24E0EB0, PATCH_RET_ZERO_FLOAT, sizeof(PATCH_RET_ZERO_FLOAT) },
    { "Gphz.set_FinalDead() — block local finaldead set",       0x2606770, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    { "Gphz.LocalFinalDead() — block local finaldead trigger",  0x2603F00, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
    { "OnFinalDead(RPC) — block server final death",            0x1F70870, PATCH_RET_VOID,       sizeof(PATCH_RET_VOID) },
};
static const size_t FINALDEAD_TARGET_COUNT = sizeof(FINALDEAD_TARGETS) / sizeof(FINALDEAD_TARGETS[0]);
static const char*  FINALDEAD_BACKUP       = "dmmdzz_finaldead_backup.bin";

// ---------------------------------------------------------------------------
// Weapon patch targets — set weapon fire interval to zero (rapid fire).
//
// ROOT CAUSE ANALYSIS (v1..v9 ALL FAILED):
//
//   v1: FlowEvaluatorWeaponCanFire.Execute() → true.  WRONG: AI behaviour tree.
//   v2: VZBaawHT...(bool,bool) & SBGZcbjf...(bool,int) → true.  WRONG: VZBaawHT
//       is per-frame UI update; SBGZcbjf IS the fire body (patching entry
//       skips projectile spawn + DmmRPC).
//   v3: Patched get_rPirEepR... (RVA 0x2829A90) → user float.  FAILED (wrong
//       getter — TryFire calls get_VHPoHMEu, not get_rPirEepR).
//   v4: Inline patch of TryFire addss at RVA 0x28231D6.  FAILED (wrong path).
//   v5: Two-layer patch (BatchUpdate jb nop + TryFire addss).  FAILED.
//   v7: Patched get_VHPoHMEu entry → return 0.0f.  FAILED: TryFire's non-
//       generic path checks `cmp ax, 2` (FireCritType enum), NOT the float
//       value.  EAX=0 → ax=0 → selects constant2 (same as original).
//   v8: Patched get_VHPoHMEu → return EAX=2 (IntervalFire).  FAILED: the
//       constants at [0x66981314]/[0x66980CD0] are unknown, and the generic
//       path (if taken) bypasses the thunk entry entirely.
//   v9: Patched ALL THREE movss in TryFire → xorps xmm0,xmm0 (0.0f).
//       FAILED: PATCH VERIFIED but "still has interval".
//       ROOT CAUSE: TryFire is NOT the fire-interval gate. The real gate is
//       the CALLER of TryFire — method MpuZoNzOGNLWsvNLdMFjqnEqqjiTSHoFJHAxWkHA
//       at RVA 0x281E000 (dump.cs line 123965).  This method:
//         1. Checks [esi+0x187] (firing flag); if 0, returns.
//         2. Runs two CanFire-like bool checks.
//         3. Calls a float method to get the REMAINING fire interval.
//         4. comiss xmm1, xmm0 (compares interval vs 0.0f)
//         5. ja 0x640CE0EC  → if interval > 0, DELAYED-FIRE path
//                            (schedules future fire, does NOT call TryFire)
//         6. fall-through  → IMMEDIATE-FIRE path:
//              a. mov byte [esi+0x187], 0   (clears firing flag)
//              b. call TryFire(eax, 0.0f)   (fires NOW)
//       TryFire is only called when interval <= 0, so patching TryFire's
//       movss is meaningless. The comiss/ja gate in RVA 0x281E000 is the
//       true gate.
//
// V10 APPROACH — patch the comiss/ja gate in RVA 0x281E000:
//
//   Patch A: NOP the `ja` (RVA 0x281E0C1, 2 bytes: 77 27 → 90 90).
//            Forces IMMEDIATE-FIRE path every time regardless of interval.
//
//   Patch B: NOP the flag-clear (RVA 0x281E0C6, 7 bytes:
//            C6 86 87 01 00 00 00 → 90*7).
//            Immediate-fire path clears [esi+0x187] after firing.  If
//            StartFire only sets the flag on key-down (not every frame),
//            clearing it would result in firing only ONE shot per press.
//            NOP-ing keeps the flag set so it fires every frame while held.
//            EndFire (separate method) clears the flag on key-up.
//
//   Risk: if EndFire does NOT clear [esi+0x187], weapon fires forever
//   after first key-press.  If so, drop Patch B and only keep Patch A.
//   No custom float support in v10 (always 0 interval = fire every frame).
// ---------------------------------------------------------------------------
// The TRUE fire-interval gate method (caller of TryFire):
//   dump.cs line 123965: private void MpuZoNzOGNLWsvNLdMFjqnEqqjiTSHoFJHAxWkHA()
//   RVA 0x281E000, VA 0x640CE000
static const uintptr_t WEAPON_GATE_JA_RVA         = 0x281E0C1; // ja 0x640CE0EA         (2 bytes: 77 27)
static const uintptr_t WEAPON_GATE_FLAGCLEAR_RVA  = 0x281E0C6; // mov byte [esi+0x187],0 (7 bytes: C6 86 87 01 00 00 00)
static const char*  WEAPON_BACKUP          = "dmmdzz_weapon_backup.bin";

// ===========================================================================
// Utility
// ===========================================================================
static void PrintHex(const void* data, size_t size, uintptr_t baseVA)
{
    const uint8_t* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; i += 16) {
        std::printf("  %016llX  ", static_cast<unsigned long long>(baseVA + i));
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size) std::printf("%02X ", p[i + j]);
            else              std::printf("   ");
            if (j == 7) std::printf(" ");
        }
        std::printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; ++j) {
            uint8_t c = p[i + j];
            std::printf("%c", (c >= 0x20 && c < 0x7F) ? (char)c : '.');
        }
        std::printf("|\n");
    }
}

// Convert narrow argv -> wide string. Simple ASCII is enough for image names.
static std::wstring ToWide(const char* s)
{
    if (!s) return L"";
    return std::wstring(s, s + std::strlen(s));
}

// ---------------------------------------------------------------------------
// Elevation helpers
//
// The controller needs Administrator privileges to enable SeDebugPrivilege,
// open the driver device, and operate on other processes. If not elevated,
// RelaunchAsAdmin() re-spawns itself with the "runas" verb (triggers UAC),
// forwards the original command line, waits for the elevated copy, and
// mirrors its exit code.
// ---------------------------------------------------------------------------
static bool IsElevated()
{
    BOOL elevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te;
        DWORD cb = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &cb))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated != FALSE;
}

static int RelaunchAsAdmin(int argc, char** argv)
{
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    // Build parameter string from argv[1..] (skip the exe path itself).
    std::wstring params;
    for (int i = 1; i < argc; i++) {
        if (i > 1) params += L" ";
        std::wstring wa = ToWide(argv[i]);
        // Quote if it contains spaces and isn't already quoted.
        if (wa.find(L' ') != std::wstring::npos &&
            (wa.empty() || wa.front() != L'"'))
            params += L"\"" + wa + L"\"";
        else
            params += wa;
    }

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = params.c_str();
    sei.nShow  = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        std::fprintf(stderr,
            "[!] Failed to elevate (ShellExecuteEx error %lu).\n"
            "    Please run as Administrator manually.\n", GetLastError());
        return 1;
    }

    // Wait for the elevated child and mirror its exit code.
    int exitCode = 0;
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(sei.hProcess, &code);
        exitCode = (int)code;
        CloseHandle(sei.hProcess);
    }
    return exitCode;
}

// ---------------------------------------------------------------------------
// KDU auto-map helpers
//
// Pure KDU workflow: the driver is never registered as an SCM service. If the
// device is not already open, we look for kdu.exe + *_kdu.sys next to this
// executable and run "kdu.exe -map <sys>" to manually map the driver, then
// retry opening the device.
// ---------------------------------------------------------------------------
static std::wstring ExeDirectory()
{
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring dir(exePath);
    size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir.resize(slash + 1);
    else dir = L".\\";
    return dir;
}

// Find the first *_kdu.sys in the same directory as this exe.
static std::wstring FindKduSysFile()
{
    std::wstring dir = ExeDirectory();
    std::wstring pattern = dir + L"*_kdu.sys";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return L"";
    std::wstring path = dir + fd.cFileName;
    FindClose(hFind);
    return path;
}

// Run kdu.exe -map <sysPath> synchronously in the same directory.
static bool RunKduMap(const std::wstring& sysPath)
{
    std::wstring dir = ExeDirectory();
    std::wstring kduPath = dir + L"kdu.exe";
    if (GetFileAttributesW(kduPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::printf("[!] kdu.exe not found next to controller.\n");
        return false;
    }

    std::wstring cmd = L"\"" + kduPath + L"\" -map \"" + sysPath + L"\"";

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, const_cast<LPWSTR>(cmd.c_str()),
                        nullptr, nullptr, FALSE, 0, nullptr,
                        dir.c_str(), &si, &pi)) {
        std::printf("[!] CreateProcess(kdu.exe) failed (err=%lu)\n", GetLastError());
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::printf("[*] kdu.exe exited with code %lu\n", exitCode);
    return exitCode == 0;
}

// Common setup: ensure Administrator, enable SeDebugPrivilege, open the driver
// device. If the device is not present, auto-map the driver via KDU and retry.
static bool OpenDriver(dmmdzz::DriverCtl& drv)
{
    dmmdzz::EnableDebugPrivilege();

    std::printf("[*] Probing device %ls ...\n", WIN32_DEVICE_PATH);
    if (drv.TryOpen()) {
        std::printf("[+] Device already available (driver pre-loaded).\n");
        return true;
    }

    std::printf("[*] Device not found, attempting KDU manual map...\n");
    std::wstring kduSys = FindKduSysFile();
    if (kduSys.empty()) {
        std::printf("[!] No *_kdu.sys found next to controller.\n");
        return false;
    }
    std::printf("[*] Found driver image: %ls\n", kduSys.c_str());

    if (!RunKduMap(kduSys)) {
        std::printf("[!] KDU manual map failed.\n");
        return false;
    }

    std::printf("[*] Retrying device open...\n");
    if (drv.TryOpen()) {
        std::printf("[+] Device opened after KDU map.\n");
        return true;
    }

    std::printf("[!] Device still not available after KDU map.\n");
    return false;
}

// Look up the GameAssembly.dll base in the target process. IL2CPP-compiled
// method bodies live in GameAssembly.dll, so this is the base we add RVAs to.
static uintptr_t GetGameAssemblyBase(dmmdzz::DriverCtl& drv, uint32_t pid,
                                     OUT uint32_t* sizeOfImage = nullptr)
{
    uintptr_t base = 0;
    uint32_t  size = 0;
    drv.EnumModule(pid, L"GameAssembly.dll", &base, &size);
    if (sizeOfImage) *sizeOfImage = size;
    return base;
}

// ---------------------------------------------------------------------------
// ScanPattern — scan a range of memory in the target process for a byte
// pattern. Returns a list of RVAs (relative to dllBase) where the pattern
// was found.
//
// Uses overlapping reads to catch matches that straddle chunk boundaries:
// each iteration advances by (chunkSize - patternLen + 1) bytes, so the last
// (patternLen - 1) bytes of each chunk are re-scanned in the next iteration.
//
// Optional mask: if mask is non-null, mask[i]=0 means "wildcard" (match any
// byte at position i). This lets us scan `8B 41 ?? C3` to enumerate all
// simple int getters regardless of field offset.
// ---------------------------------------------------------------------------
static std::vector<uintptr_t> ScanPattern(dmmdzz::DriverCtl& drv, uint32_t pid,
                                          uintptr_t dllBase, uint32_t dllSize,
                                          const uint8_t* pattern, size_t patternLen,
                                          const uint8_t* mask = nullptr)
{
    std::vector<uintptr_t> results;
    if (dllSize == 0 || patternLen == 0) return results;

    std::vector<uint8_t> buf(SCAN_CHUNK);
    uintptr_t addr = dllBase;
    uintptr_t end  = dllBase + dllSize;
    // Overlap ensures cross-boundary matches are caught.
    size_t advance = SCAN_CHUNK - (patternLen - 1);

    std::printf("[*] Scanning 0x%X bytes of GameAssembly.dll for %zu-byte pattern: ",
                dllSize, patternLen);
    for (size_t i = 0; i < patternLen; ++i) {
        if (mask && mask[i] == 0) std::printf("?? ");
        else                       std::printf("%02X ", pattern[i]);
    }
    std::printf("\n");

    size_t scanned = 0;
    while (addr < end) {
        size_t toRead = std::min(SCAN_CHUNK, (size_t)(end - addr));
        try {
            drv.ReadMemory(pid, addr, buf.data(), toRead);
        } catch (...) {
            // Read failed (unmapped page etc.) — skip this chunk
            addr += advance;
            continue;
        }

        for (size_t i = 0; i + patternLen <= toRead; ++i) {
            bool match = true;
            for (size_t j = 0; j < patternLen; ++j) {
                if (mask && mask[j] == 0) continue;  // wildcard
                if (buf[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) {
                uintptr_t matchVA = addr + i;
                results.push_back(matchVA - dllBase);  // RVA
            }
        }

        scanned += toRead;
        if (addr + toRead >= end) break;
        addr += advance;
    }

    std::printf("[*] Scanned %zu bytes, found %zu match(es).\n",
                scanned, results.size());
    return results;
}

// ===========================================================================
// Subcommand: freecard
//   Patches CardUtility.CanBuyCard and CanPlayerUseCard to always return
//   true, bypassing the client-side ownership/gold checks for prop cards.
//   Combined with the 'patch' subcommand (get_Price→1), this makes every
//   prop card usable in battle regardless of gold or ownership.
//
//   Usage:
//     freecard <game.exe>   - patch both check methods
//
//   Backup format (dmmdzz_freecard_backup.bin):
//     [4-byte count][count × (8-byte RVA + 16-byte original)]
// ===========================================================================
static int CmdFreeCard(const std::wstring& target)
{
    std::printf("=== dmmdzz_injector - FREECARD (bypass prop card checks) ===\n");
    std::printf("Target image: %ls\n", target.c_str());
    std::printf("Patching %zu methods (lobby currency + in-game battle gold):\n", FREECARD_TARGET_COUNT);
    for (size_t i = 0; i < FREECARD_TARGET_COUNT; ++i)
        std::printf("  [%zu] %-50s RVA=0x%llX\n", i, FREECARD_TARGETS[i].name,
                    static_cast<unsigned long long>(FREECARD_TARGETS[i].rva));
    std::printf("----------------------------------------------------------\n");

    try {
        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        DMMDZZ_VERSION v{};
        drv.GetVersion(v);
        std::printf("[+] Driver version: %u.%u.%u\n", v.Major, v.Minor, v.Build);

        // 1. Find target process
        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        // 2. Find GameAssembly.dll base
        uint32_t  dllSize = 0;
        uintptr_t dllBase = GetGameAssemblyBase(drv, pid, &dllSize);
        if (dllBase == 0) {
            std::fprintf(stderr,
                "[!] GameAssembly.dll not found in target.\n");
            return 1;
        }
        std::printf("[+] GameAssembly.dll base=0x%016llX size=0x%X\n",
                    static_cast<unsigned long long>(dllBase), dllSize);

        // 3. Prepare backup buffer
        struct BackupEntry {
            uintptr_t rva;
            uint8_t   original[PATCH_REGION];
        };
        std::vector<BackupEntry> backups(FREECARD_TARGET_COUNT);

        // 4. Patch each target
        bool allOk = true;
        for (size_t i = 0; i < FREECARD_TARGET_COUNT; ++i) {
            uintptr_t rva      = FREECARD_TARGETS[i].rva;
            uintptr_t targetVA = dllBase + rva;

            std::printf("\n--- [%zu] %s ---\n", i, FREECARD_TARGETS[i].name);
            std::printf("    VA=0x%016llX (base + RVA 0x%llX)\n",
                        static_cast<unsigned long long>(targetVA),
                        static_cast<unsigned long long>(rva));

            // Read original bytes
            uint8_t original[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, original, PATCH_REGION);
            std::printf("    Original %zu bytes:\n", PATCH_REGION);
            PrintHex(original, PATCH_REGION, targetVA);

            // Save for backup
            backups[i].rva = rva;
            std::memcpy(backups[i].original, original, PATCH_REGION);

            // Check if already patched (idempotent)
            if (std::memcmp(original, FREECARD_TARGETS[i].patch, FREECARD_TARGETS[i].patchLen) == 0) {
                std::printf("    [+] Already patched, skipping.\n");
                continue;
            }

            // Write patch
            std::printf("    Writing %zu-byte patch: ", FREECARD_TARGETS[i].patchLen);
            for (size_t j = 0; j < FREECARD_TARGETS[i].patchLen; ++j)
                std::printf("%02X ", FREECARD_TARGETS[i].patch[j]);
            std::printf("\n");
            drv.WriteMemory(pid, targetVA, FREECARD_TARGETS[i].patch, FREECARD_TARGETS[i].patchLen);

            // Verify
            uint8_t after[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, after, PATCH_REGION);
            if (std::memcmp(after, FREECARD_TARGETS[i].patch, FREECARD_TARGETS[i].patchLen) == 0) {
                std::printf("    [+] PATCH VERIFIED.\n");
            } else {
                std::fprintf(stderr, "    [!] Patch verification FAILED!\n");
                allOk = false;
            }
        }

        // 5. Save backup file
        FILE* fp = std::fopen(FREECARD_BACKUP, "wb");
        if (!fp) {
            std::fprintf(stderr, "[!] Failed to open backup file '%s' for write\n",
                         FREECARD_BACKUP);
            return 1;
        }
        uint32_t count = (uint32_t)FREECARD_TARGET_COUNT;
        if (std::fwrite(&count, sizeof(count), 1, fp) != 1) {
            std::fclose(fp);
            std::fprintf(stderr, "[!] Failed to write backup count\n");
            return 1;
        }
        for (size_t i = 0; i < FREECARD_TARGET_COUNT; ++i) {
            if (std::fwrite(&backups[i].rva, sizeof(uintptr_t), 1, fp) != 1 ||
                std::fwrite(backups[i].original, 1, PATCH_REGION, fp) != PATCH_REGION) {
                std::fclose(fp);
                std::fprintf(stderr, "[!] Failed to write backup entry %zu\n", i);
                return 1;
            }
        }
        std::fclose(fp);
        std::printf("\n[+] Saved %zu entries to '%s'\n",
                    FREECARD_TARGET_COUNT, FREECARD_BACKUP);

        if (allOk) {
            std::printf("[+] FREECARD COMPLETE. Prop card checks bypassed.\n");
            std::printf("    Run 'dmmdzz_ctl.exe restorecard %ls' to undo.\n",
                        target.c_str());
            return 0;
        } else {
            std::fprintf(stderr,
                "[!] Some patches failed. Check output above.\n");
            return 1;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

// ===========================================================================
// Subcommand: restorecard
//   Reads dmmdzz_freecard_backup.bin and restores original bytes for all
//   freecard patches.
//
//   Usage:
//     restorecard <game.exe>
// ===========================================================================
static int CmdRestoreCard(const std::wstring& target)
{
    std::printf("=== dmmdzz_injector - RESTORECARD (undo freecard patches) ===\n");
    std::printf("Target image: %ls\n", target.c_str());
    std::printf("----------------------------------------------------------\n");

    try {
        // 1. Read backup file
        FILE* fp = std::fopen(FREECARD_BACKUP, "rb");
        if (!fp) {
            std::fprintf(stderr,
                "[!] Backup file '%s' not found. Cannot restore.\n",
                FREECARD_BACKUP);
            return 1;
        }
        uint32_t count = 0;
        if (std::fread(&count, sizeof(count), 1, fp) != 1) {
            std::fclose(fp);
            std::fprintf(stderr, "[!] Backup file malformed (no count).\n");
            return 1;
        }
        std::printf("[*] Backup contains %u entries.\n", count);

        struct BackupEntry {
            uintptr_t rva;
            uint8_t   original[PATCH_REGION];
        };
        std::vector<BackupEntry> backups(count);
        for (uint32_t i = 0; i < count; ++i) {
            if (std::fread(&backups[i].rva, sizeof(uintptr_t), 1, fp) != 1 ||
                std::fread(backups[i].original, 1, PATCH_REGION, fp) != PATCH_REGION) {
                std::fclose(fp);
                std::fprintf(stderr, "[!] Backup file truncated at entry %u.\n", i);
                return 1;
            }
        }
        std::fclose(fp);

        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        // 2. Find target process
        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        // 3. Find GameAssembly.dll
        uintptr_t dllBase = GetGameAssemblyBase(drv, pid);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found in target.\n");
            return 1;
        }

        // 4. Restore each entry
        bool allOk = true;
        for (uint32_t i = 0; i < count; ++i) {
            uintptr_t targetVA = dllBase + backups[i].rva;
            std::printf("\n--- [%u] RVA=0x%llX  VA=0x%016llX ---\n",
                        i,
                        static_cast<unsigned long long>(backups[i].rva),
                        static_cast<unsigned long long>(targetVA));

            // Show current bytes
            uint8_t current[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, current, PATCH_REGION);
            std::printf("    Current bytes:\n");
            PrintHex(current, PATCH_REGION, targetVA);

            // Write original back
            drv.WriteMemory(pid, targetVA, backups[i].original, PATCH_REGION);

            // Verify
            uint8_t after[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, after, PATCH_REGION);
            if (std::memcmp(after, backups[i].original, PATCH_REGION) == 0) {
                std::printf("    [+] RESTORE VERIFIED.\n");
            } else {
                std::fprintf(stderr, "    [!] Restore verification FAILED!\n");
                allOk = false;
            }
        }

        if (allOk) {
            std::printf("\n[+] RESTORECARD COMPLETE. All freecard patches undone.\n");
            return 0;
        } else {
            std::fprintf(stderr, "\n[!] Some restores failed. Check output above.\n");
            return 1;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

// ===========================================================================
// Generic patch helpers — used by antiacheat (and future commands).
// ===========================================================================

// Apply patches to memory and save backup file. Returns 0 on success.
static int ApplyPatchTargets(dmmdzz::DriverCtl& drv, uint32_t pid, uintptr_t dllBase,
                             const FreeCardTarget* targets, size_t count,
                             const char* backupFile, const char* label)
{
    struct BackupEntry {
        uintptr_t rva;
        uint8_t   original[PATCH_REGION];
    };
    std::vector<BackupEntry> backups(count);

    bool allOk = true;
    for (size_t i = 0; i < count; ++i) {
        uintptr_t rva      = targets[i].rva;
        uintptr_t targetVA = dllBase + rva;

        std::printf("\n--- [%zu] %s ---\n", i, targets[i].name);
        std::printf("    VA=0x%016llX (base + RVA 0x%llX)\n",
                    static_cast<unsigned long long>(targetVA),
                    static_cast<unsigned long long>(rva));

        uint8_t original[PATCH_REGION] = {};
        drv.ReadMemory(pid, targetVA, original, PATCH_REGION);
        std::printf("    Original %zu bytes:\n", PATCH_REGION);
        PrintHex(original, PATCH_REGION, targetVA);

        backups[i].rva = rva;
        std::memcpy(backups[i].original, original, PATCH_REGION);

        if (std::memcmp(original, targets[i].patch, targets[i].patchLen) == 0) {
            std::printf("    [+] Already patched, skipping.\n");
            continue;
        }

        std::printf("    Writing %zu-byte patch: ", targets[i].patchLen);
        for (size_t j = 0; j < targets[i].patchLen; ++j)
            std::printf("%02X ", targets[i].patch[j]);
        std::printf("\n");
        drv.WriteMemory(pid, targetVA, targets[i].patch, targets[i].patchLen);

        uint8_t after[PATCH_REGION] = {};
        drv.ReadMemory(pid, targetVA, after, PATCH_REGION);
        if (std::memcmp(after, targets[i].patch, targets[i].patchLen) == 0) {
            std::printf("    [+] PATCH VERIFIED.\n");
        } else {
            std::fprintf(stderr, "    [!] Patch verification FAILED!\n");
            allOk = false;
        }
    }

    FILE* fp = std::fopen(backupFile, "wb");
    if (!fp) {
        std::fprintf(stderr, "[!] Failed to open backup file '%s' for write\n", backupFile);
        return 1;
    }
    uint32_t n = (uint32_t)count;
    if (std::fwrite(&n, sizeof(n), 1, fp) != 1) {
        std::fclose(fp);
        std::fprintf(stderr, "[!] Failed to write backup count\n");
        return 1;
    }
    for (size_t i = 0; i < count; ++i) {
        if (std::fwrite(&backups[i].rva, sizeof(uintptr_t), 1, fp) != 1 ||
            std::fwrite(backups[i].original, 1, PATCH_REGION, fp) != PATCH_REGION) {
            std::fclose(fp);
            std::fprintf(stderr, "[!] Failed to write backup entry %zu\n", i);
            return 1;
        }
    }
    std::fclose(fp);
    std::printf("\n[+] Saved %zu entries to '%s'\n", count, backupFile);

    if (allOk) {
        std::printf("[+] %s COMPLETE.\n", label);
        return 0;
    } else {
        std::fprintf(stderr, "[!] Some patches failed. Check output above.\n");
        return 1;
    }
}

// Restore original bytes from backup file. Returns 0 on success.
static int RestorePatchTargets(dmmdzz::DriverCtl& drv, uint32_t pid, uintptr_t dllBase,
                               const char* backupFile, const char* label)
{
    FILE* fp = std::fopen(backupFile, "rb");
    if (!fp) {
        std::fprintf(stderr, "[!] Backup file '%s' not found. Cannot restore.\n", backupFile);
        return 1;
    }
    uint32_t count = 0;
    if (std::fread(&count, sizeof(count), 1, fp) != 1) {
        std::fclose(fp);
        std::fprintf(stderr, "[!] Backup file malformed (no count).\n");
        return 1;
    }
    std::printf("[*] Backup contains %u entries.\n", count);

    struct BackupEntry {
        uintptr_t rva;
        uint8_t   original[PATCH_REGION];
    };
    std::vector<BackupEntry> backups(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (std::fread(&backups[i].rva, sizeof(uintptr_t), 1, fp) != 1 ||
            std::fread(backups[i].original, 1, PATCH_REGION, fp) != PATCH_REGION) {
            std::fclose(fp);
            std::fprintf(stderr, "[!] Backup file truncated at entry %u.\n", i);
            return 1;
        }
    }
    std::fclose(fp);

    bool allOk = true;
    for (uint32_t i = 0; i < count; ++i) {
        uintptr_t targetVA = dllBase + backups[i].rva;
        std::printf("\n--- [%u] RVA=0x%llX  VA=0x%016llX ---\n",
                    i,
                    static_cast<unsigned long long>(backups[i].rva),
                    static_cast<unsigned long long>(targetVA));

        uint8_t current[PATCH_REGION] = {};
        drv.ReadMemory(pid, targetVA, current, PATCH_REGION);
        std::printf("    Current bytes:\n");
        PrintHex(current, PATCH_REGION, targetVA);

        drv.WriteMemory(pid, targetVA, backups[i].original, PATCH_REGION);

        uint8_t after[PATCH_REGION] = {};
        drv.ReadMemory(pid, targetVA, after, PATCH_REGION);
        if (std::memcmp(after, backups[i].original, PATCH_REGION) == 0) {
            std::printf("    [+] RESTORE VERIFIED.\n");
        } else {
            std::fprintf(stderr, "    [!] Restore verification FAILED!\n");
            allOk = false;
        }
    }

    if (allOk) {
        std::printf("\n[+] %s COMPLETE.\n", label);
        return 0;
    } else {
        std::fprintf(stderr, "\n[!] Some restores failed. Check output above.\n");
        return 1;
    }
}

// ===========================================================================
// Subcommand: antiacheat
//   Disables all cheat-detection functions (IsCheat, NotifyCheating, etc).
//   Run BEFORE freecard so detection is neutralized before tampering.
// ===========================================================================
static int CmdAntiCheat(const std::wstring& target)
{
    std::printf("=== dmmdzz_injector - ANTIACHEAT (disable cheat detection) ===\n");
    std::printf("Target image: %ls\n", target.c_str());
    std::printf("Patching %zu anti-cheat functions:\n", ANTI_CHEAT_TARGET_COUNT);
    for (size_t i = 0; i < ANTI_CHEAT_TARGET_COUNT; ++i)
        std::printf("  [%zu] %-50s RVA=0x%llX\n", i, ANTI_CHEAT_TARGETS[i].name,
                    static_cast<unsigned long long>(ANTI_CHEAT_TARGETS[i].rva));
    std::printf("----------------------------------------------------------\n");

    try {
        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        uint32_t  dllSize = 0;
        uintptr_t dllBase = GetGameAssemblyBase(drv, pid, &dllSize);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found in target.\n");
            return 1;
        }
        std::printf("[+] GameAssembly.dll base=0x%016llX size=0x%X\n",
                    static_cast<unsigned long long>(dllBase), dllSize);

        return ApplyPatchTargets(drv, pid, dllBase,
                                 ANTI_CHEAT_TARGETS, ANTI_CHEAT_TARGET_COUNT,
                                 ANTI_CHEAT_BACKUP, "ANTIACHEAT");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

// ===========================================================================
// Subcommand: restoreantiacheat
//   Restores original bytes for all antiacheat patches.
// ===========================================================================
static int CmdRestoreAntiCheat(const std::wstring& target)
{
    std::printf("=== dmmdzz_injector - RESTOREANTIACHEAT (undo anti-cheat patches) ===\n");
    std::printf("Target image: %ls\n", target.c_str());
    std::printf("----------------------------------------------------------\n");

    try {
        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        uintptr_t dllBase = GetGameAssemblyBase(drv, pid);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found in target.\n");
            return 1;
        }

        return RestorePatchTargets(drv, pid, dllBase,
                                   ANTI_CHEAT_BACKUP, "RESTOREANTIACHEAT");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

// ===========================================================================
// Subcommand: cd
//   Patches prop card cooldown to 0 (minimum). 18 targets covering all layers:
//
//   ObjectSegment overrides (the ACTUAL runtime getters — virtual dispatch):
//     ObjSeg<object>.get_Cooldown              RVA 0x33570E0 → 0.0f
//     ObjSeg<object>.get_CooldownOnEnd         RVA 0x3357090 → 0.0f
//     ObjSeg<object>.get_WaitTriggerTime       RVA 0x3357E70 → 0.0f
//     ObjSeg<__Shared>.get_Cooldown            RVA 0x3357130 → 0.0f
//     ObjSeg<__Shared>.get_CooldownOnEnd       RVA 0x3357000 → 0.0f
//     ObjSeg<__Shared>.get_WaitTriggerTime     RVA 0x3357EC0 → 0.0f
//   Base class fallback:
//     InGameStoreInfo.get_Cooldown (base)      RVA 0x716990  → 0.0f
//     InGameStoreInfo.get_CooldownOnEnd (base)  RVA 0x726280  → 0.0f
//   CD discount:
//     EPropertyComp.GetPropCardCdDiscount      RVA 0x40CCAA0 → 1.0f
//     PlayerController.GetPropCardCdDiscount   RVA 0x1EAA4B0 → 1.0f
//   Runtime CD gate:
//     InGameInteractionButton.CheckIsCoolDown  RVA 0x23D5100 → false
//     InGameInteractionButton.GetPropCooldownTime RVA 0x23D6460 → 0.0f
//   InGameStore-level CD (store-wide + per-card SafeDictionary gate):
//     InGameStore.GetCardCdRemain(StoreInfo)   RVA 0x256EE80 → 0.0f
//     InGameStore.GetCardCdRemainById(int)     RVA 0x25799C0 → 0.0f
//     InGameStore.IsInCoolDown()               RVA 0x2579690 → false
//     InGameStore.SetCardCd(int,float)         RVA 0x25765F0 → no-op
//     InGameStore.SetCardCdEx(int,float,bool,int) RVA 0x2576700 → no-op
//     InGameStore.SetCardCdPublic(int,float)   RVA 0x2570900 → no-op
//
//   ROOT CAUSE of "cd has no effect": InGameStoreInfo properties are VIRTUAL.
//   Runtime instances are InGameStoreInfoObjectSegment<T> (ZeroFormatter).
//   Virtual dispatch goes to ObjectSegment overrides, NOT base class methods.
//   Previous patches targeted base class getters (0x716990, 0x726280) which
//   were NEVER called at runtime — the ObjectSegment overrides (0x3357xxx)
//   were the actual methods executed. Additionally, WaitTriggerTime (the delay
//   before a card can trigger) was completely unpatched.
//
//   For the "CD only works once" issue (server blocks subsequent uses when
//   gold is insufficient), run 'talent' before 'cd' to make the free-purchase
//   talent fire 100% (CheckTrigger → true).
//
//   Usage:
//     cd <game.exe>
//
//   Backup format (dmmdzz_cd_backup.bin):
//     [4-byte count][count × (8-byte RVA + 16-byte original)]
// ===========================================================================
static int CmdCd(const std::wstring& target)
{
    std::printf("=== dmmdzz_injector - CD (set prop card cooldown to minimum) ===\n");
    std::printf("Target image: %ls\n", target.c_str());
    std::printf("Patching %zu methods (cooldown → 0):\n", CD_TARGET_COUNT);
    for (size_t i = 0; i < CD_TARGET_COUNT; ++i)
        std::printf("  [%zu] %-50s RVA=0x%llX\n", i, CD_TARGETS[i].name,
                    static_cast<unsigned long long>(CD_TARGETS[i].rva));
    std::printf("----------------------------------------------------------\n");

    try {
        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        DMMDZZ_VERSION v{};
        drv.GetVersion(v);
        std::printf("[+] Driver version: %u.%u.%u\n", v.Major, v.Minor, v.Build);

        // 1. Find target process
        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        // 2. Find GameAssembly.dll base
        uint32_t  dllSize = 0;
        uintptr_t dllBase = GetGameAssemblyBase(drv, pid, &dllSize);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found in target.\n");
            return 1;
        }
        std::printf("[+] GameAssembly.dll base=0x%016llX size=0x%X\n",
                    static_cast<unsigned long long>(dllBase), dllSize);

        // 3. Prepare backup buffer
        struct BackupEntry {
            uintptr_t rva;
            uint8_t   original[PATCH_REGION];
        };
        std::vector<BackupEntry> backups(CD_TARGET_COUNT);

        // 4. Patch each target
        bool allOk = true;
        for (size_t i = 0; i < CD_TARGET_COUNT; ++i) {
            uintptr_t rva      = CD_TARGETS[i].rva;
            uintptr_t targetVA = dllBase + rva;

            std::printf("\n--- [%zu] %s ---\n", i, CD_TARGETS[i].name);
            std::printf("    VA=0x%016llX (base + RVA 0x%llX)\n",
                        static_cast<unsigned long long>(targetVA),
                        static_cast<unsigned long long>(rva));

            // Read original bytes
            uint8_t original[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, original, PATCH_REGION);
            std::printf("    Original %zu bytes:\n", PATCH_REGION);
            PrintHex(original, PATCH_REGION, targetVA);

            // Save for backup
            backups[i].rva = rva;
            std::memcpy(backups[i].original, original, PATCH_REGION);

            // Check if already patched (idempotent)
            if (std::memcmp(original, CD_TARGETS[i].patch, CD_TARGETS[i].patchLen) == 0) {
                std::printf("    [+] Already patched, skipping.\n");
                continue;
            }

            // Write patch
            std::printf("    Writing %zu-byte patch: ", CD_TARGETS[i].patchLen);
            for (size_t j = 0; j < CD_TARGETS[i].patchLen; ++j)
                std::printf("%02X ", CD_TARGETS[i].patch[j]);
            std::printf("\n");
            drv.WriteMemory(pid, targetVA, CD_TARGETS[i].patch, CD_TARGETS[i].patchLen);

            // Verify
            uint8_t after[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, after, PATCH_REGION);
            if (std::memcmp(after, CD_TARGETS[i].patch, CD_TARGETS[i].patchLen) == 0) {
                std::printf("    [+] PATCH VERIFIED.\n");
            } else {
                std::fprintf(stderr, "    [!] Patch verification FAILED!\n");
                allOk = false;
            }
        }

        // 5. Save backup file
        FILE* fp = std::fopen(CD_BACKUP, "wb");
        if (!fp) {
            std::fprintf(stderr, "[!] Failed to open backup file '%s' for write\n",
                         CD_BACKUP);
            return 1;
        }
        uint32_t count = (uint32_t)CD_TARGET_COUNT;
        if (std::fwrite(&count, sizeof(count), 1, fp) != 1) {
            std::fclose(fp);
            std::fprintf(stderr, "[!] Failed to write backup count\n");
            return 1;
        }
        for (size_t i = 0; i < CD_TARGET_COUNT; ++i) {
            if (std::fwrite(&backups[i].rva, sizeof(uintptr_t), 1, fp) != 1 ||
                std::fwrite(backups[i].original, 1, PATCH_REGION, fp) != PATCH_REGION) {
                std::fclose(fp);
                std::fprintf(stderr, "[!] Failed to write backup entry %zu\n", i);
                return 1;
            }
        }
        std::fclose(fp);
        std::printf("\n[+] Saved %zu entries to '%s'\n",
                    CD_TARGET_COUNT, CD_BACKUP);

        if (allOk) {
            std::printf("[+] CD COMPLETE. Prop card cooldown set to minimum.\n");
            std::printf("    Run 'dmmdzz_ctl.exe restorecd %ls' to undo.\n",
                        target.c_str());
            return 0;
        } else {
            std::fprintf(stderr,
                "[!] Some patches failed. Check output above.\n");
            return 1;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

// ===========================================================================
// Subcommand: restorecd
//   Reads dmmdzz_cd_backup.bin and restores original bytes for all
//   cooldown patches.
//
//   Usage:
//     restorecd <game.exe>
// ===========================================================================
static int CmdRestoreCd(const std::wstring& target)
{
    std::printf("=== dmmdzz_injector - RESTORECD (undo cooldown patches) ===\n");
    std::printf("Target image: %ls\n", target.c_str());
    std::printf("----------------------------------------------------------\n");

    try {
        // 1. Read backup file
        FILE* fp = std::fopen(CD_BACKUP, "rb");
        if (!fp) {
            std::fprintf(stderr,
                "[!] Backup file '%s' not found. Cannot restore.\n",
                CD_BACKUP);
            return 1;
        }
        uint32_t count = 0;
        if (std::fread(&count, sizeof(count), 1, fp) != 1) {
            std::fclose(fp);
            std::fprintf(stderr, "[!] Backup file malformed (no count).\n");
            return 1;
        }
        std::printf("[*] Backup contains %u entries.\n", count);

        struct BackupEntry {
            uintptr_t rva;
            uint8_t   original[PATCH_REGION];
        };
        std::vector<BackupEntry> backups(count);
        for (uint32_t i = 0; i < count; ++i) {
            if (std::fread(&backups[i].rva, sizeof(uintptr_t), 1, fp) != 1 ||
                std::fread(backups[i].original, 1, PATCH_REGION, fp) != PATCH_REGION) {
                std::fclose(fp);
                std::fprintf(stderr, "[!] Backup file truncated at entry %u.\n", i);
                return 1;
            }
        }
        std::fclose(fp);

        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        // 2. Find target process
        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        // 3. Find GameAssembly.dll
        uintptr_t dllBase = GetGameAssemblyBase(drv, pid);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found in target.\n");
            return 1;
        }

        // 4. Restore each entry
        bool allOk = true;
        for (uint32_t i = 0; i < count; ++i) {
            uintptr_t targetVA = dllBase + backups[i].rva;
            std::printf("\n--- [%u] RVA=0x%llX  VA=0x%016llX ---\n",
                        i,
                        static_cast<unsigned long long>(backups[i].rva),
                        static_cast<unsigned long long>(targetVA));

            // Show current bytes
            uint8_t current[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, current, PATCH_REGION);
            std::printf("    Current bytes:\n");
            PrintHex(current, PATCH_REGION, targetVA);

            // Write original back
            drv.WriteMemory(pid, targetVA, backups[i].original, PATCH_REGION);

            // Verify
            uint8_t after[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, after, PATCH_REGION);
            if (std::memcmp(after, backups[i].original, PATCH_REGION) == 0) {
                std::printf("    [+] RESTORE VERIFIED.\n");
            } else {
                std::fprintf(stderr, "    [!] Restore verification FAILED!\n");
                allOk = false;
            }
        }

        if (allOk) {
            std::printf("\n[+] RESTORECD COMPLETE. All cooldown patches undone.\n");
            return 0;
        } else {
            std::fprintf(stderr, "\n[!] Some restores failed. Check output above.\n");
            return 1;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

// ===========================================================================
// Generic patch/restore helpers (used by talent / golddemon subcommands)
// ===========================================================================
static int ApplyPatches(const std::wstring& target, const char* banner,
                        const FreeCardTarget* targets, size_t targetCount,
                        const char* backupFile)
{
    std::printf("=== dmmdzz_injector - %s ===\n", banner);
    std::printf("Target image: %ls\n", target.c_str());
    std::printf("Patching %zu methods:\n", targetCount);
    for (size_t i = 0; i < targetCount; ++i)
        std::printf("  [%zu] %-50s RVA=0x%llX\n", i, targets[i].name,
                    static_cast<unsigned long long>(targets[i].rva));
    std::printf("----------------------------------------------------------\n");

    try {
        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        DMMDZZ_VERSION v{};
        drv.GetVersion(v);
        std::printf("[+] Driver version: %u.%u.%u\n", v.Major, v.Minor, v.Build);

        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        uint32_t  dllSize = 0;
        uintptr_t dllBase = GetGameAssemblyBase(drv, pid, &dllSize);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found in target.\n");
            return 1;
        }
        std::printf("[+] GameAssembly.dll base=0x%016llX size=0x%X\n",
                    static_cast<unsigned long long>(dllBase), dllSize);

        struct BackupEntry {
            uintptr_t rva;
            uint8_t   original[PATCH_REGION];
        };
        std::vector<BackupEntry> backups(targetCount);

        bool allOk = true;
        for (size_t i = 0; i < targetCount; ++i) {
            uintptr_t rva      = targets[i].rva;
            uintptr_t targetVA = dllBase + rva;

            std::printf("\n--- [%zu] %s ---\n", i, targets[i].name);
            std::printf("    VA=0x%016llX (base + RVA 0x%llX)\n",
                        static_cast<unsigned long long>(targetVA),
                        static_cast<unsigned long long>(rva));

            uint8_t original[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, original, PATCH_REGION);
            std::printf("    Original %zu bytes:\n", PATCH_REGION);
            PrintHex(original, PATCH_REGION, targetVA);

            backups[i].rva = rva;
            std::memcpy(backups[i].original, original, PATCH_REGION);

            if (std::memcmp(original, targets[i].patch, targets[i].patchLen) == 0) {
                std::printf("    [+] Already patched, skipping.\n");
                continue;
            }

            std::printf("    Writing %zu-byte patch: ", targets[i].patchLen);
            for (size_t j = 0; j < targets[i].patchLen; ++j)
                std::printf("%02X ", targets[i].patch[j]);
            std::printf("\n");
            drv.WriteMemory(pid, targetVA, targets[i].patch, targets[i].patchLen);

            uint8_t after[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, after, PATCH_REGION);
            if (std::memcmp(after, targets[i].patch, targets[i].patchLen) == 0) {
                std::printf("    [+] PATCH VERIFIED.\n");
            } else {
                std::fprintf(stderr, "    [!] Patch verification FAILED!\n");
                allOk = false;
            }
        }

        FILE* fp = std::fopen(backupFile, "wb");
        if (!fp) {
            std::fprintf(stderr, "[!] Failed to open backup file '%s' for write\n",
                         backupFile);
            return 1;
        }
        uint32_t count = (uint32_t)targetCount;
        if (std::fwrite(&count, sizeof(count), 1, fp) != 1) {
            std::fclose(fp);
            std::fprintf(stderr, "[!] Failed to write backup count\n");
            return 1;
        }
        for (size_t i = 0; i < targetCount; ++i) {
            if (std::fwrite(&backups[i].rva, sizeof(uintptr_t), 1, fp) != 1 ||
                std::fwrite(backups[i].original, 1, PATCH_REGION, fp) != PATCH_REGION) {
                std::fclose(fp);
                std::fprintf(stderr, "[!] Failed to write backup entry %zu\n", i);
                return 1;
            }
        }
        std::fclose(fp);
        std::printf("\n[+] Saved %zu entries to '%s'\n", targetCount, backupFile);

        if (allOk) {
            std::printf("[+] PATCH COMPLETE.\n");
            return 0;
        } else {
            std::fprintf(stderr, "[!] Some patches failed. Check output above.\n");
            return 1;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

static int RestorePatches(const std::wstring& target, const char* banner,
                          const char* backupFile)
{
    std::printf("=== dmmdzz_injector - %s ===\n", banner);
    std::printf("Target image: %ls\n", target.c_str());
    std::printf("----------------------------------------------------------\n");

    try {
        FILE* fp = std::fopen(backupFile, "rb");
        if (!fp) {
            std::fprintf(stderr, "[!] Backup file '%s' not found. Cannot restore.\n",
                         backupFile);
            return 1;
        }
        uint32_t count = 0;
        if (std::fread(&count, sizeof(count), 1, fp) != 1) {
            std::fclose(fp);
            std::fprintf(stderr, "[!] Backup file malformed (no count).\n");
            return 1;
        }
        std::printf("[*] Backup contains %u entries.\n", count);

        struct BackupEntry {
            uintptr_t rva;
            uint8_t   original[PATCH_REGION];
        };
        std::vector<BackupEntry> backups(count);
        for (uint32_t i = 0; i < count; ++i) {
            if (std::fread(&backups[i].rva, sizeof(uintptr_t), 1, fp) != 1 ||
                std::fread(backups[i].original, 1, PATCH_REGION, fp) != PATCH_REGION) {
                std::fclose(fp);
                std::fprintf(stderr, "[!] Backup file truncated at entry %u.\n", i);
                return 1;
            }
        }
        std::fclose(fp);

        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        uintptr_t dllBase = GetGameAssemblyBase(drv, pid);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found in target.\n");
            return 1;
        }

        bool allOk = true;
        for (uint32_t i = 0; i < count; ++i) {
            uintptr_t targetVA = dllBase + backups[i].rva;
            std::printf("\n--- [%u] RVA=0x%llX  VA=0x%016llX ---\n",
                        i,
                        static_cast<unsigned long long>(backups[i].rva),
                        static_cast<unsigned long long>(targetVA));

            uint8_t current[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, current, PATCH_REGION);
            std::printf("    Current bytes:\n");
            PrintHex(current, PATCH_REGION, targetVA);

            drv.WriteMemory(pid, targetVA, backups[i].original, PATCH_REGION);

            uint8_t after[PATCH_REGION] = {};
            drv.ReadMemory(pid, targetVA, after, PATCH_REGION);
            if (std::memcmp(after, backups[i].original, PATCH_REGION) == 0) {
                std::printf("    [+] RESTORE VERIFIED.\n");
            } else {
                std::fprintf(stderr, "    [!] Restore verification FAILED!\n");
                allOk = false;
            }
        }

        if (allOk) {
            std::printf("\n[+] RESTORE COMPLETE.\n");
            return 0;
        } else {
            std::fprintf(stderr, "\n[!] Some restores failed. Check output above.\n");
            return 1;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

// ===========================================================================
// Subcommand: talent / restoretalent
//   Makes CheckTrigger return true → 100% talent trigger (SelfHelpDevil /
//   free-purchase talent fires every time the player is downed).
// ===========================================================================
static int CmdTalent(const std::wstring& target)
{
    return ApplyPatches(target, "TALENT (100% talent trigger)",
                        TALENT_TARGETS, TALENT_TARGET_COUNT, TALENT_BACKUP);
}

static int CmdRestoreTalent(const std::wstring& target)
{
    return RestorePatches(target, "RESTORETALENT (undo talent patches)",
                          TALENT_BACKUP);
}

// ===========================================================================
// Subcommand: skillcd / restoreskillcd
//   Removes active skill cooldown. 7 targets covering ALL 3 CD tracker
//   classes (SkillCD, gcPUCg, vfUKKv) + RoleSkill legacy getters.
//
//   Only getter methods are patched — state management (Update, OnUseSkill,
//   Reset) runs normally to avoid breaking the CD state machine.
//
//   Usage:
//     skillcd <game.exe>
// ===========================================================================
static int CmdSkillCd(const std::wstring& target)
{
    return ApplyPatches(target, "SKILLCD (remove active skill cooldown)",
                        SKILLCD_TARGETS, SKILLCD_TARGET_COUNT, SKILLCD_BACKUP);
}

static int CmdRestoreSkillCd(const std::wstring& target)
{
    return RestorePatches(target, "RESTORESKILLCD (undo skill cd patches)",
                          SKILLCD_BACKUP);
}

// ===========================================================================
// Subcommand: zombie_thief / zombie_police / zombie / restorezombie_*
//
//   Keeps the player acting after HP reaches 0.  Patches state getters
//   (IsDying/IsDead/FinalDead) to return false, blocks FinalDead setters
//   and RPC, and (for thief) forces get_MoveSpeed→5.0f + CanMove→true.
//
//   This does NOT lock HP (server-authoritative, impossible via byte patch).
//   HP still drops to 0 on the server, but the client ignores the dead/dying
//   state and continues to function.
//
//   SIDE EFFECT: ALL players appear "not dead" on the local screen (byte
//   patches affect all PlayerController instances).  Dead enemies may appear
//   alive locally.  The server still tracks real death state.
//
//   Usage:
//     zombie_thief   <game.exe>   Patch for thief role (dQhho class)
//     zombie_police  <game.exe>   Patch for police role (Gphz class)
//     zombie         <game.exe>   Patch all (legacy, both roles)
//     restorezombie_thief   <game.exe>
//     restorezombie_police  <game.exe>
//     restorezombie         <game.exe>
// ===========================================================================

// Helper: merge two target arrays into a vector and apply
static int ApplyMergedPatches(const std::wstring& target, const char* banner,
                              const FreeCardTarget* t1, size_t n1,
                              const FreeCardTarget* t2, size_t n2,
                              const char* backupFile)
{
    std::vector<FreeCardTarget> merged;
    merged.reserve(n1 + n2);
    for (size_t i = 0; i < n1; ++i) merged.push_back(t1[i]);
    for (size_t i = 0; i < n2; ++i) merged.push_back(t2[i]);
    return ApplyPatches(target, banner,
                        merged.data(), merged.size(),
                        backupFile);
}

static int CmdZombieThief(const std::wstring& target)
{
    int ret = ApplyMergedPatches(target,
        "ZOMBIE_THIEF (act after HP=0 — thief, full speed + prop cards)",
        ZOMBIE_COMMON_TARGETS, sizeof(ZOMBIE_COMMON_TARGETS)/sizeof(ZOMBIE_COMMON_TARGETS[0]),
        ZOMBIE_THIEF_TARGETS,  sizeof(ZOMBIE_THIEF_TARGETS)/sizeof(ZOMBIE_THIEF_TARGETS[0]),
        ZOMBIE_THIEF_BACKUP);
    if (ret == 0) {
        std::printf("\n[!] Thief zombie patch applied.\n");
        std::printf("    get_MoveSpeed→5.0f, CanMove→true, UpdateMoveSpeed→no-op.\n");
        std::printf("    State getters→false, FinalDead setters/RPC blocked.\n");
        std::printf("    Run 'restorezombie_thief' to undo.\n");
    }
    return ret;
}

static int CmdRestoreZombieThief(const std::wstring& target)
{
    return RestorePatches(target, "RESTOREZOMBIE_THIEF (undo thief zombie patches)",
                          ZOMBIE_THIEF_BACKUP);
}

static int CmdZombiePolice(const std::wstring& target)
{
    // Police-specific targets are currently empty (Gphz IS the police base
    // class, so all necessary targets are in ZOMBIE_COMMON_TARGETS).
    // When police-specific targets are added, switch to ApplyMergedPatches.
    int ret = ApplyPatches(target,
        "ZOMBIE_POLICE (act after HP=0 — police, ignore dead state)",
        ZOMBIE_COMMON_TARGETS, sizeof(ZOMBIE_COMMON_TARGETS)/sizeof(ZOMBIE_COMMON_TARGETS[0]),
        ZOMBIE_POLICE_BACKUP);
    if (ret == 0) {
        std::printf("\n[!] Police zombie patch applied.\n");
        std::printf("    State getters→false, FinalDead setters/RPC blocked.\n");
        std::printf("    Run 'restorezombie_police' to undo.\n");
    }
    return ret;
}

static int CmdRestoreZombiePolice(const std::wstring& target)
{
    return RestorePatches(target, "RESTOREZOMBIE_POLICE (undo police zombie patches)",
                          ZOMBIE_POLICE_BACKUP);
}

// Legacy: patch everything (common + thief)
static int CmdZombie(const std::wstring& target)
{
    // Merge common + thief (police has no extra targets currently)
    std::vector<FreeCardTarget> merged;
    size_t nc = sizeof(ZOMBIE_COMMON_TARGETS)/sizeof(ZOMBIE_COMMON_TARGETS[0]);
    size_t nt = sizeof(ZOMBIE_THIEF_TARGETS)/sizeof(ZOMBIE_THIEF_TARGETS[0]);
    merged.reserve(nc + nt);
    for (size_t i = 0; i < nc; ++i) merged.push_back(ZOMBIE_COMMON_TARGETS[i]);
    for (size_t i = 0; i < nt; ++i) merged.push_back(ZOMBIE_THIEF_TARGETS[i]);

    int ret = ApplyPatches(target, "ZOMBIE (act after HP=0 — all roles)",
                           merged.data(), merged.size(),
                           ZOMBIE_BACKUP);
    if (ret == 0) {
        std::printf("\n[!] HP will still drop to 0 (server-authoritative).\n");
        std::printf("    But the client ignores the dead/dying state, so you\n");
        std::printf("    can keep moving and using prop cards after HP=0.\n");
        std::printf("    Run 'restorezombie' to undo.\n");
    }
    return ret;
}

static int CmdRestoreZombie(const std::wstring& target)
{
    return RestorePatches(target, "RESTOREZOMBIE (undo zombie patches)",
                          ZOMBIE_BACKUP);
}

// ===========================================================================
// Subcommand: finaldead / restorefinaldead
//
//   Blocks the Dying → FinalDead transition. Use this to stay in Dying state
//   indefinitely (never permanently die). Can be used standalone or combined
//   with zombie_thief.
//
//   Usage:
//     finaldead         <game.exe>   Block FinalDead transition
//     restorefinaldead  <game.exe>   Undo finaldead patches
// ===========================================================================
static int CmdFinalDead(const std::wstring& target)
{
    int ret = ApplyPatches(target,
        "FINALDEAD (block Dying→FinalDead transition)",
        FINALDEAD_TARGETS, FINALDEAD_TARGET_COUNT,
        FINALDEAD_BACKUP);
    if (ret == 0) {
        std::printf("\n[!] FinalDead patch applied.\n");
        std::printf("    set_FinalDead→no-op, LocalFinalDead→no-op, OnFinalDead(RPC)→no-op.\n");
        std::printf("    Player will stay in Dying state, never progress to FinalDead.\n");
        std::printf("    Run 'restorefinaldead' to undo.\n");
    }
    return ret;
}

static int CmdRestoreFinalDead(const std::wstring& target)
{
    return RestorePatches(target, "RESTOREFINALDEAD (undo finaldead patches)",
                          FINALDEAD_BACKUP);
}

// ===========================================================================
// Subcommand: weapon / restoreweapon
//   Sets the weapon fire interval to zero (rapid fire).
//
//   v10: Patches the comiss/ja gate in MpuZoNzOGNLWsvNLdMFjqnEqqjiTSHoFJHAxWkHA
//   (RVA 0x281E000) — the TRUE fire-interval gate (caller of TryFire).
//
//   Patch A: NOP `ja` (RVA 0x281E0C3, 2 bytes) → forces immediate fire.
//   Patch B: NOP flag-clear (RVA 0x281E0C8, 7 bytes) → keeps firing flag set
//            so the weapon fires every frame while the key is held.
//
//   Usage:
//     weapon        → rapid fire (fire every frame while key held)
//     weapon 0.1    → same (v10 ignores the float parameter)
// ===========================================================================
static int CmdWeapon(const std::wstring& target, float /*seconds*/)
{
    // NOP patch bytes
    static const uint8_t PATCH_NOP_2[] = { 0x90, 0x90 };
    static const uint8_t PATCH_NOP_7[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

    FreeCardTarget targets[] = {
        { "Gate ja → nop (force immediate-fire path)",
          WEAPON_GATE_JA_RVA, PATCH_NOP_2, sizeof(PATCH_NOP_2) },
        { "Gate flag-clear → nop (keep firing flag set)",
          WEAPON_GATE_FLAGCLEAR_RVA, PATCH_NOP_7, sizeof(PATCH_NOP_7) },
    };

    return ApplyPatches(target, "WEAPON v10 (gate ja+flagclear → nop)",
                        targets, 2, WEAPON_BACKUP);
}

// ===========================================================================
// Subcommand: dumpweapon
//   Reads raw bytes at all candidate weapon getter/method RVAs and prints
//   them as hex for offline x86 disassembly. Does NOT patch anything.
//   Run 'restoreweapon' first if the primary getter was already patched.
// ===========================================================================
struct DumpTarget { const char* name; uintptr_t rva; size_t size; };

static int CmdDumpWeapon(const std::wstring& target)
{
    // v6: After v5 (BatchUpdate jb + TryFire addss) failed, the real fire gate
    // must be in a method that CALLS TryFire (SBGZcbjf, VA 0x640D1470). The
    // strongest candidates are Slot 26 (input handler), the two same-prefix
    // public methods (likely StartFire/EndFire pair), and the Slot 25 virtual.
    // Dump sizes capped at 4096 to keep output manageable for offline review.
    static const DumpTarget dumps[] = {
        // --- Primary fire-gate candidates (callers of TryFire) ---
        { "XZmLjWibnVQrnRUwlBxdnsyZpMZlMTpAYNZQczug(bool,bool) Slot26 — input handler?",
                                                                              0x2825BC0, 4096 },
        { "KgwLsxrrBHrTeDwjsqVcngzbKaAWlggvwgIVraYW() — StartFire?",          0x281D9C0, 4096 },
        { "wLsxrrBHrTeDwjsJWDaVngzbKaAWlggvwgIVraYW() — EndFire?",            0x282DAB0, 4096 },
        { "griuyCGCBHkbqbmXbIMIWmtgKgJiZtxtvwOQhQdM() Slot25 — virtual void", 0x282A240, 4096 },
        { "UsNNrKNftHimUXiWxgzSgxoiGZliWHHgBHUnwZdi() — public void",         0x2824650, 4096 },
        { "SsiHiuQuOjdwlVZVeBcbxTJWZwZiuiFYXafzTzVv(bool) — private void",    0x2823B90, 4096 },
        { "dPLfWFEzpNjdfYfcDPbgfzPcrannfrjcBfztWcEv(float,float) — time-based?", 0x2828210, 4096 },
        // --- Reference: WeaponStartFire RPC (network entry, for cross-check) ---
        { "GMlDbMWbQOWdMqtsCUOsTOkwTGZjxkfrQkNQuFNX() [DmmRPC 25031] WeaponStartFire",
                                                                              0x281B760, 2048 },
        // --- Reference: TryFire body (so we can match its VA 0x640D1470 in callers) ---
        { "SBGZcbjf...(bool,int) (TryFire body, VA 0x640D1470)",              0x2821470, 1024 },
    };
    const size_t dumpCount = sizeof(dumps) / sizeof(dumps[0]);

    std::printf("=== DUMPWEAPON (read raw bytes for disassembly) ===\n");
    std::printf("Target image: %ls\n", target.c_str());

    try {
        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        uintptr_t dllBase = GetGameAssemblyBase(drv, pid);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found.\n");
            return 1;
        }
        std::printf("[+] GameAssembly.dll base=0x%016llX\n\n",
                    static_cast<unsigned long long>(dllBase));

        for (size_t i = 0; i < dumpCount; ++i) {
            uintptr_t va = dllBase + dumps[i].rva;
            std::vector<uint8_t> buf(dumps[i].size, 0);
            drv.ReadMemory(pid, va, buf.data(), buf.size());

            std::printf("--- [%zu] %s ---\n", i, dumps[i].name);
            std::printf("    RVA=0x%llX  VA=0x%016llX  %zu bytes\n",
                        static_cast<unsigned long long>(dumps[i].rva),
                        static_cast<unsigned long long>(va),
                        dumps[i].size);
            PrintHex(buf.data(), buf.size(), va);
            std::printf("\n");
        }

        std::printf("[+] Dump complete. Paste this output for disassembly.\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

static int CmdRestoreWeapon(const std::wstring& target)
{
    return RestorePatches(target, "RESTOREWEAPON (undo weapon fire interval patch)",
                          WEAPON_BACKUP);
}

// ===========================================================================
// Subcommand: dumpcard
//   Dumps raw bytes of client-side prop-card release methods for offline
//   disassembly. Purpose: locate the CLIENT-SIDE gold/coin check that gates
//   LPlaceableUtil.ReqUseCard RPC send (so we can bypass it and make the
//   client send the use-card RPC even when local gold is insufficient).
//
//   Background:
//     - Patching IsCostFreeMode → true only affects UI display; in real
//       (online) matches the client still refuses to send ReqUseCard.
//     - CostGold / OnRpcSubCoin are server-side and not called on the
//       client before the RPC, so patching them on the client has no effect.
//     - The real client-side gate must be in qntQLIdkYbsyNepXxGnYwKfGVDcQCzROJAvkhcnu
//       (the card-logic component held by InGameInteractionButton.m_cardLogic @0x15C),
//       most likely inside OnButtonUp or the private bool YzCvqpayczgbhkaouydbFdUFBBLBkuCotkBjRpGo.
// ===========================================================================
static int CmdDumpCard(const std::wstring& target)
{
    // RVAs from dump.cs (IL2CPP x86, fastcall + caller cleanup).
    // qntQLIdkYbsyNepXxGnYwKfGVDcQCzROJAvkhcnu = TypeDefIndex 2698 (line 126465).
    // InGameInteractionButton                     = TypeDefIndex 1516 (line 68560).
    // LPlaceableUtil.ReqUseCard                   = line 1416358.
    static const DumpTarget dumps[] = {
        // --- PRIMARY gate candidates (client-side card-logic component) ---
        // OnButtonUp(bool tryCancel) returns bool — THE release gate.
        { "qntQL...OnButtonUp(bool) — RELEASE GATE (returns bool)",       0x286C530, 4096 },
        // vNolvNIBahZUEylkyelkFSZuKqYSkHSfkHmvRbTy — calls LPlaceableUtil.ReqUseCard (RPC send)
        { "qntQL...vNolvNIB...(V3,V3,V3,CachedBuf<int>) — RPC SEND",      0x2870500, 2048 },
        // YzCvqpayczgbhkaouydbFdUFBBLBkuCotkBjRpGo() — private bool, likely "can use" check
        { "qntQL...YzCvqpay...() — private bool can-use check",           0x286D820, 1024 },
        // VNSVdfUjwDUppXpNXuYGmYKALnZpLGGgGMgVPHJP() — returns context struct
        { "qntQL...VNSVdfUjw...() — get context (no args)",               0x286D5A0, 1024 },
        // VNSVdfUjwDUppXpNXuYGmYKALnZpLGGgGMgVPHJP(V3,V3,V3) — get context with positions
        { "qntQL...VNSVdfUjw...(V3,V3,V3) — get context (positions)",     0x286D460, 1024 },
        // OnButtonDown() — for context (what happens on press)
        { "qntQL...OnButtonDown() — press handler",                       0x286BDB0, 2048 },
        // bpCmlziWAvfxmSGbsJuxtjASksQjtdfoyNekUldJ(PlayerController,Info) — init/setup
        { "qntQL...bpCmlziWA...(PlayerController, InGameStoreInfo) — init",0x286DB70, 1024 },
        // --- UI button entry points (for cross-checking call flow) ---
        // InGameInteractionButton.StartUsing() returns bool
        { "InGameInteractionButton.StartUsing() — UI entry (bool)",       0x23D81B0, 2048 },
        // InGameInteractionButton.EndUsing(bool,bool) — UI exit
        { "InGameInteractionButton.EndUsing(bool,bool) — UI exit",        0x23D5C20, 2048 },
        // InGameInteractionButton.SetCoinCost(int) — sets m_CoinCost (0x128)
        { "InGameInteractionButton.SetCoinCost(int) — set price field",   0x23D6DA0, 512  },
        // InGameInteractionButton.UpdatePriceText() — reads cost for UI
        { "InGameInteractionButton.UpdatePriceText() — UI price text",    0x23DB3B0, 1024 },
        // --- RPC send reference (server-side L util, but called by client) ---
        // LPlaceableUtil.ReqUseCard(...) — creates LMNAEvent_ReqUseCard, sends to server
        { "LPlaceableUtil.ReqUseCard(...) — RPC send (reference)",        0x411FB80, 2048 },
    };
    const size_t dumpCount = sizeof(dumps) / sizeof(dumps[0]);

    std::printf("=== DUMPCARD (read raw bytes for disassembly) ===\n");
    std::printf("Target image: %ls\n", target.c_str());

    try {
        dmmdzz::DriverCtl drv;
        OpenDriver(drv);

        uintptr_t eProcVA = 0;
        uint32_t  pid = drv.FindProcess(target, &eProcVA);
        std::printf("[+] Target PID=%u\n", pid);

        uintptr_t dllBase = GetGameAssemblyBase(drv, pid);
        if (dllBase == 0) {
            std::fprintf(stderr, "[!] GameAssembly.dll not found.\n");
            return 1;
        }
        std::printf("[+] GameAssembly.dll base=0x%016llX\n\n",
                    static_cast<unsigned long long>(dllBase));

        for (size_t i = 0; i < dumpCount; ++i) {
            uintptr_t va = dllBase + dumps[i].rva;
            std::vector<uint8_t> buf(dumps[i].size, 0);
            drv.ReadMemory(pid, va, buf.data(), buf.size());

            std::printf("--- [%zu] %s ---\n", i, dumps[i].name);
            std::printf("    RVA=0x%llX  VA=0x%016llX  %zu bytes\n",
                        static_cast<unsigned long long>(dumps[i].rva),
                        static_cast<unsigned long long>(va),
                        dumps[i].size);
            PrintHex(buf.data(), buf.size(), va);
            std::printf("\n");
        }

        std::printf("[+] Dump complete. Paste this output for disassembly analysis.\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[!] Error: %s\n", e.what());
        return 1;
    }
}

// ===========================================================================
// Interactive REPL mode
//
// Launch with no arguments to enter. Auto-hide/unhide is handled by main().
// Supports all subcommands plus 'hide' (DKOM hide this process) and 'unhide'
// (restore) for manual toggle. 'exit'/EOF returns to main() which unhides.
// ===========================================================================
static void PrintUsage(const char* argv0);  // forward decl

static int RunRepl(bool& hidden)
{
    std::printf("===鸢尾花v0.0.1 命令行交互版===\n");
    if (hidden) {
        std::printf("    Task manager / NtQuerySystemInformation will no longer list it.\n");
    }
    std::printf("输入help并回车查看可用学习项目，输入exit并回车退出.\n");
    
    std::string line;

    while (true) {
        std::printf("dzz> ");
        std::fflush(stdout);
        if (!std::getline(std::cin, line)) {
            break;  // EOF — main() handles unhide
        }

        // Trim leading/trailing whitespace
        size_t s = line.find_first_not_of(" \t");
        if (s == std::string::npos) continue;
        size_t e = line.find_last_not_of(" \t");
        line = line.substr(s, e - s + 1);

        // Split sub + rest
        std::string sub, rest;
        size_t sp = line.find_first_of(" \t");
        if (sp == std::string::npos) {
            sub = line;
        } else {
            sub  = line.substr(0, sp);
            rest = line.substr(sp + 1);
            size_t rs = rest.find_first_not_of(" \t");
            if (rs != std::string::npos) rest = rest.substr(rs);
            else rest.clear();
        }

        // --- REPL-only commands ---
        if (sub == "exit" || sub == "quit") {
            break;  // main() handles unhide
        }
        if (sub == "hide") {
            if (hidden) { std::printf("[*] Already hidden.\n"); continue; }
            try {
                dmmdzz::DriverCtl drv; OpenDriver(drv);
                uint32_t pid = GetCurrentProcessId();
                uintptr_t eProc = drv.HideProcess(pid);
                std::printf("[+] Process hidden: PID=%u EPROCESS=0x%016llX\n",
                            pid, static_cast<unsigned long long>(eProc));
                hidden = true;
            } catch (const std::exception& ex) {
                std::printf("[!] Hide failed: %s\n", ex.what());
            }
            continue;
        }
        if (sub == "unhide") {
            try {
                dmmdzz::DriverCtl drv; OpenDriver(drv);
                drv.UnhideProcess();
                std::printf("[+] Process restored to ActiveProcessLinks.\n");
                hidden = false;
            } catch (const std::exception& ex) {
                std::printf("[!] Unhide failed: %s\n", ex.what());
            }
            continue;
        }
        if (sub == "help" || sub == "?" || sub == "-h" || sub == "--help") {
            PrintUsage("dmmdzz_ctl");
            continue;
        }

        // --- Patch subcommands (all target dmmdzz.exe) ---
        const std::wstring target = L"dmmdzz.exe";

        if      (sub == "antiacheat")          CmdAntiCheat(target);
        else if (sub == "restoreantiacheat")   CmdRestoreAntiCheat(target);
        else if (sub == "freecard")            CmdFreeCard(target);
        else if (sub == "restorecard")         CmdRestoreCard(target);
        else if (sub == "cd")                  CmdCd(target);
        else if (sub == "restorecd")           CmdRestoreCd(target);
        else if (sub == "talent")              CmdTalent(target);
        else if (sub == "restoretalent")       CmdRestoreTalent(target);
        else if (sub == "skillcd")             CmdSkillCd(target);
        else if (sub == "restoreskillcd")      CmdRestoreSkillCd(target);
        else if (sub == "zombie_thief")        CmdZombieThief(target);
        else if (sub == "restorezombie_thief") CmdRestoreZombieThief(target);
        else if (sub == "zombie_police")       CmdZombiePolice(target);
        else if (sub == "restorezombie_police")CmdRestoreZombiePolice(target);
        else if (sub == "zombie")              CmdZombie(target);
        else if (sub == "restorezombie")       CmdRestoreZombie(target);
        else if (sub == "finaldead")           CmdFinalDead(target);
        else if (sub == "restorefinaldead")    CmdRestoreFinalDead(target);
        else if (sub == "weapon") {
            float secs = 0.0f;
            if (!rest.empty()) {
                try { secs = std::stof(rest); }
                catch (...) {
                    std::printf("[!] Invalid seconds: '%s' (usage: weapon [seconds])\n", rest.c_str());
                    continue;
                }
            }
            CmdWeapon(target, secs);
        }
        else if (sub == "restoreweapon")       CmdRestoreWeapon(target);
        else if (sub == "dumpweapon")          CmdDumpWeapon(target);
        else if (sub == "dumpcard")            CmdDumpCard(target);
        else std::printf("[!] Unknown command: '%s' (type 'help')\n", sub.c_str());
    }
    return 0;
}

// ===========================================================================
// Usage
// ===========================================================================
static void PrintUsage(const char* argv0)
{
    std::printf(
        "Usage:\n"
        "  %s                         Interactive REPL (auto-loads driver, auto-hides)\n"
        "  %s <command>               Run a single patch command (all target dmmdzz.exe)\n"
        "\n"
        "Commands:\n"
        "  antiacheat                   Disable all cheat-detection functions (run FIRST)\n"
        "  restoreantiacheat            Restore anti-cheat patches\n"
        "  freecard                     Bypass prop card gold checks (lobby + in-game)\n"
        "  restorecard                  Restore freecard patches\n"
        "  cd                           Set prop card cooldown to minimum (0)\n"
        "  restorecd                    Restore cooldown patches\n"
        "  talent                       100%% talent trigger (SelfHelpDevil / free-purchase)\n"
        "  restoretalent                Restore talent patches\n"
        "  skillcd                      Remove active skill cooldown (all skills)\n"
        "  restoreskillcd               Restore skill cooldown patches\n"
        "  zombie_thief                 Act after HP=0 — THIEF (full speed + prop cards)\n"
        "  zombie_police                Act after HP=0 — POLICE (ignore dead state)\n"
        "  zombie                       Act after HP=0 — ALL roles (legacy)\n"
        "  finaldead                    Block Dying→FinalDead transition\n"
        "  restorezombie_thief          Restore thief zombie patches\n"
        "  restorezombie_police         Restore police zombie patches\n"
        "  restorezombie                Restore all zombie patches\n"
        "  restorefinaldead             Restore finaldead patches\n"
        "  weapon [seconds]             Set fire interval (default 0 = unlimited fire, 0.1 = rapid)\n"
        "  restoreweapon                Restore weapon fire interval patch\n"
        "  dumpweapon                   Dump raw bytes of all weapon getter candidates\n"
        "  dumpcard                     Dump raw bytes of client-side card-release methods\n"
        "  help | --help | -h            Show this help\n"
        "\n"
        "REPL-only commands (available inside the interactive shell):\n"
        "  hide        DKOM hide this process from task manager\n"
        "  unhide      Restore to ActiveProcessLinks\n"
        "  exit/quit   Leave REPL (auto-unhides if hidden)\n"
        "\n"
        "On startup (REPL mode) the driver is auto-loaded via KDU if not present,\n"
        "and this process is auto-hidden via DKOM.\n"
        "\n"
        "Backup files:\n"
        "  %s   (antiacheat: [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (freecard: [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (cd:       [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (talent:   [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (skillcd:  [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (zombie_thief:  [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (zombie_police: [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (zombie:        [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (finaldead:     [4-byte count][count x (8-byte RVA + 16-byte original)])\n"
        "  %s   (weapon:        [4-byte count][count x (8-byte RVA + 16-byte original)])\n",
        argv0, argv0,
        ANTI_CHEAT_BACKUP,
        FREECARD_BACKUP, CD_BACKUP, TALENT_BACKUP, SKILLCD_BACKUP,
        ZOMBIE_THIEF_BACKUP, ZOMBIE_POLICE_BACKUP, ZOMBIE_BACKUP, FINALDEAD_BACKUP,
        WEAPON_BACKUP);
}

// ===========================================================================
// main
// ===========================================================================
int main(int argc, char** argv)
{
    // Set console to UTF-8 so Chinese characters display correctly.
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    // Elevation: the controller needs Administrator to enable SeDebugPrivilege
    // and open the driver device. If not elevated, re-spawn via UAC and wait.
    if (!IsElevated()) {
        return RelaunchAsAdmin(argc, argv);
    }

    // Help — no driver needed, skip hide/unhide.
    if (argc >= 2) {
        std::string sub0 = argv[1];
        if (sub0 == "help" || sub0 == "--help" || sub0 == "-h") {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    // Auto-hide on startup (DKOM via driver). main() owns the hide lifecycle so
    // both REPL and single-command modes are consistently covered: hide on
    // every startup, unhide on every exit.
    bool hidden = false;
    try {
        dmmdzz::DriverCtl bootDrv;
        if (OpenDriver(bootDrv)) {
            uint32_t pid = GetCurrentProcessId();
            uintptr_t eProc = bootDrv.HideProcess(pid);
            std::printf("[+] Process hidden on startup: PID=%u EPROCESS=0x%016llX\n",
                        pid, static_cast<unsigned long long>(eProc));
            std::printf("    Task manager / NtQuerySystemInformation will no longer list it.\n");
            hidden = true;
        } else {
            std::printf("[!] Cannot open driver device. Continuing without hide.\n");
        }
    } catch (const std::exception& ex) {
        std::printf("[!] Startup hide failed: %s\n", ex.what());
    }

    int ret = 0;

    // No arguments → interactive REPL.
    if (argc < 2) {
        ret = RunRepl(hidden);
    } else {
        std::string sub = argv[1];
        const std::wstring target = L"dmmdzz.exe";

        if      (sub == "antiacheat")          ret = CmdAntiCheat(target);
        else if (sub == "restoreantiacheat")   ret = CmdRestoreAntiCheat(target);
        else if (sub == "freecard")            ret = CmdFreeCard(target);
        else if (sub == "restorecard")         ret = CmdRestoreCard(target);
        else if (sub == "cd")                  ret = CmdCd(target);
        else if (sub == "restorecd")           ret = CmdRestoreCd(target);
        else if (sub == "talent")              ret = CmdTalent(target);
        else if (sub == "restoretalent")       ret = CmdRestoreTalent(target);
        else if (sub == "skillcd")             ret = CmdSkillCd(target);
        else if (sub == "restoreskillcd")      ret = CmdRestoreSkillCd(target);
        else if (sub == "zombie_thief")        ret = CmdZombieThief(target);
        else if (sub == "restorezombie_thief") ret = CmdRestoreZombieThief(target);
        else if (sub == "zombie_police")       ret = CmdZombiePolice(target);
        else if (sub == "restorezombie_police")ret = CmdRestoreZombiePolice(target);
        else if (sub == "zombie")              ret = CmdZombie(target);
        else if (sub == "restorezombie")       ret = CmdRestoreZombie(target);
        else if (sub == "finaldead")           ret = CmdFinalDead(target);
        else if (sub == "restorefinaldead")    ret = CmdRestoreFinalDead(target);
        else if (sub == "weapon") {
            float secs = 0.0f;
            if (argc >= 3) {
                try { secs = std::stof(argv[2]); }
                catch (...) { /* ignore parse error, use default 0.0 */ }
            }
            ret = CmdWeapon(target, secs);
        }
        else if (sub == "restoreweapon")       ret = CmdRestoreWeapon(target);
        else if (sub == "dumpweapon")          ret = CmdDumpWeapon(target);
        else if (sub == "dumpcard")            ret = CmdDumpCard(target);
        else {
            PrintUsage(argv[0]);
            ret = 1;
        }
    }

    // Auto-unhide on exit.
    if (hidden) {
        std::printf("[*] Auto-unhiding process before exit...\n");
        try {
            dmmdzz::DriverCtl drv;
            OpenDriver(drv);
            drv.UnhideProcess();
        } catch (const std::exception& ex) {
            std::printf("[!] Unhide failed: %s\n", ex.what());
        }
    }

    return ret;
}
