/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 *
 * pins.c -- PIN codes and security issues
 *
 */
#include "pins.h"
#include "ae_config.h"
#include <string.h>
#include "sha256.h"
#include "delay.h"
#include "rng.h"
#include "verify.h"
#include "constant_time.h"
#include "storage.h"
#include "clocks.h"

// Number of iterations for KDF
#define KDF_ITER_WORDS      16
#define KDF_ITER_PIN        32

// We try to keep at least this many PIN attempts available to legit users
// - challenge: comparitor resolution is only 32 units (5 LSB not implemented)
#define MIN_TARGET_ATTEMPTS 32

#if FOR_508
// better names going forward!
#define KEYNUM_main_pin   KEYNUM_pin_1
#endif

// Pretty sure it doesn't matter, but adding some salt into our PIN->bytes[32] code
// based on the purpose of the PIN code.
//
#define PIN_PURPOSE_NORMAL          0x334d1858
#define PIN_PURPOSE_WORDS           0x2e6d6773

// Temporary hack only!
extern uint8_t      transitional_pinhash_cache[32];        // see linker-script

// Hash up a PIN for indicated purpose.
static void pin_hash(const char *pin, int pin_len, uint8_t result[32], uint32_t purpose);

// pin_is_blank()
//
// Is a specific PIN defined already? Not safe to expose this directly to callers!
//
    static bool
pin_is_blank(uint8_t keynum)
{
    uint8_t blank[32] = {0};

    ae_reset_chip();
    ae_pair_unlock();

    // Passing this check with zeros, means PIN was blank.
    // Failure here means nothing (except not blank).
    int is_blank = (ae_checkmac_hard(keynum, blank) == 0);

    // CAUTION? We've unlocked something maybe, but it's blank, so...
    ae_reset_chip();

    return is_blank;
}

// is_duress_pin()
//
    static bool
is_duress_pin(const uint8_t digest[32], bool is_blank, int *pin_kn)
{
    // duress PIN can never be blank; that means it wasn't set yet
    if(is_blank) return false;

    const int kn = KEYNUM_duress_pin;

    // LIMITATION: an active MitM could change what we write
    // to something else (wrong) and thus we'd never see that
    // the duress PIN was used.

    ae_reset_chip();
    ae_pair_unlock();
    if(ae_checkmac(kn, digest) == 0) {
        *pin_kn = kn;

        return true;
    }

    return false;
}

// is_main_pin()
//
// Do the checkmac thing using a PIN, and if it works, great.
//
    static bool
is_main_pin(const uint8_t digest[32], int *pin_kn)
{
    int kn = KEYNUM_main_pin;

    ae_reset_chip();
    ae_pair_unlock();

    if(ae_checkmac_hard(kn, digest) == 0) {
        *pin_kn = kn;

        return true;
    }

    return false;
}


// pin_hash()
//
// Hash up a string of digits in 32-byte goodness.
//
    static void
pin_hash(const char *pin, int pin_len, uint8_t result[32], uint32_t purpose)
{
    ASSERT(pin_len <= MAX_PIN_LEN);

    if(pin_len == 0) {
        // zero-length PIN is considered the "blank" one: all zero
        memset(result, 0, 32);

        return;
    }

	SHA256_CTX ctx;
    sha256_init(&ctx);

    sha256_update(&ctx, rom_secrets->pairing_secret, 32);
    sha256_update(&ctx, (uint8_t *)&purpose, 4);
    sha256_update(&ctx, (uint8_t *)pin, pin_len);

    sha256_final(&ctx, result);

    // and a second-sha256 on that, just in case.
    sha256_init(&ctx);
    sha256_update(&ctx, result, 32);
    sha256_final(&ctx, result);
}

// pin_hash_attempt()
//
// Go from PIN to heavily hashed 32-byte value, suitable for device.
//
// - brickme pin doesn't do the extra KDF step, so it can be fast
// - any call to this code will cost a PIN attempt
//
    static int
pin_hash_attempt(uint8_t target_kn, const char *pin, int pin_len, uint8_t result[32])
{
    uint8_t tmp[32]; 

    if(pin_len == 0) {
        // zero len PIN is "blank" value: all zeros, no hashing
        memset(result, 0, 32);

        return 0;
    }

    pin_hash(pin, pin_len, tmp, PIN_PURPOSE_NORMAL);

    if(target_kn == KEYNUM_brickme) {
        // no extra KDF for brickme case
        memcpy(result, tmp, 32);
    } else {
        // main, duress pins need mega hashing
        int rv = ae_kdf_iter(KEYNUM_pin_attempt, tmp, result, KDF_ITER_PIN);
        if(rv) return EPIN_AE_FAIL;
    }

    return 0;
}

// pin_prefix_words()
//
// Look up some bits... do HMAC(words secret) and return some LSB's
//
// CAUTIONS: 
// - rate-limited by the chip, since it takes this many iterations
// - hash generated is not shown on bus (thanks to IO protection)
//
    int
pin_prefix_words(const char *pin_prefix, int prefix_len, uint32_t *result)
{
    uint8_t     tmp[32];
    uint8_t     digest[32];

    // hash it up, a little
    pin_hash(pin_prefix, prefix_len, tmp, PIN_PURPOSE_WORDS);

    // With 608a, we can do same KDF stretching to get good built-in delays
    ae_setup();

    int rv = ae_kdf_iter(KEYNUM_words, tmp, digest, KDF_ITER_WORDS);

    ae_reset_chip();
	if(rv) return -1;

    // take just 32 bits of that (only 22 bits shown to user)
    memcpy(result, digest, 4);

    return 0;
}

// _hmac_attempt()
//
// Maybe should be proper HMAC from fips std? Can be changed later.
//
    static void
_hmac_attempt(const pinAttempt_t *args, uint8_t result[32])
{
    extern uint8_t      reboot_seed_base[32];        // constant per-boot

	SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, rom_secrets->pairing_secret, 32);
    sha256_update(&ctx, reboot_seed_base, 32);
    sha256_update(&ctx, (uint8_t *)args, offsetof(pinAttempt_t, hmac));

    if(args->magic_value == PA_MAGIC_V2) {
        sha256_update(&ctx, (uint8_t *)args->cached_main_pin,
                                msizeof(pinAttempt_t, cached_main_pin));
    }

    sha256_final(&ctx, result);

    // and a second-sha256 on that, just in case.
    sha256_init(&ctx);
    sha256_update(&ctx, result, 32);
    sha256_final(&ctx, result);
}

// _validate_attempt()
//
    static int
_validate_attempt(pinAttempt_t *args, bool first_time)
{
    if(first_time) {
        // no hmac needed for setup call
    } else {
        // if hmac is defined, better be right.
        uint8_t     actual[32];

        _hmac_attempt(args, actual);

        if(!check_equal(actual, args->hmac, 32)) {
            // hmac is wrong?
            return EPIN_HMAC_FAIL;
        }
    }

    // check fields.
    if(args->magic_value == PA_MAGIC_V1) {
        // ok
    } else if(args->magic_value == PA_MAGIC_V2) {
        // ok
    } else if(first_time && args->magic_value == 0) {
        // allow it if first time: implies V1 api
    } else {
        return EPIN_BAD_MAGIC;
    }

    // check fields
    if(args->pin_len > MAX_PIN_LEN) return EPIN_RANGE_ERR;
    if(args->old_pin_len > MAX_PIN_LEN) return EPIN_RANGE_ERR;
    if(args->new_pin_len > MAX_PIN_LEN) return EPIN_RANGE_ERR;
    if((args->change_flags & CHANGE__MASK) != args->change_flags) return EPIN_RANGE_ERR;

    if((args->is_secondary & 0x1) != args->is_secondary) return EPIN_RANGE_ERR;
        
    return 0;
}

// _sign_attempt()
//
// Provide our "signature" validating struct contents as coming from us.
//
    static void
_sign_attempt(pinAttempt_t *args)
{
    _hmac_attempt(args, args->hmac);
}

// _read_slot_as_counter()
//
    static int
_read_slot_as_counter(uint8_t slot, uint32_t *dest)
{
    // Read (typically a) counter value held in a dataslot.
    // Important that this be authenticated.
    //
    // - using first 32-bits only, others will be zero/ignored
    // - but need to read whole thing for the digest check

    uint32_t padded[32/4] = { 0 };
    ae_pair_unlock();
    if(ae_read_data_slot(slot, (uint8_t *)padded, 32)) return -1;

    uint8_t tempkey[32];
    ae_pair_unlock();
    if(ae_gendig_slot(slot, (const uint8_t *)padded, tempkey)) return -1;

    if(!ae_is_correct_tempkey(tempkey)) fatal_mitm();

    *dest = padded[0];

    return 0;
}


// get_last_success()
//
// Read state about previous attempt(s) from AE. Calculate number of failures,
// and how many attempts are left. The need for verifing the values from AE is
// not really so strong with the 608a, since it's all enforced on that side, but
// we'll do it anyway.
//
    static int __attribute__ ((noinline))
get_last_success(pinAttempt_t *args)
{
    const int slot = KEYNUM_lastgood;

    ae_pair_unlock();

    // Read counter value of last-good login. Important that this be authenticated.
    // - using first 32-bits only, others will be zero
    uint32_t padded[32/4] = { 0 };
    if(ae_read_data_slot(slot, (uint8_t *)padded, 32)) return -1;

    uint8_t tempkey[32];
    ae_pair_unlock();
    if(ae_gendig_slot(slot, (const uint8_t *)padded, tempkey)) return -1;

    if(!ae_is_correct_tempkey(tempkey)) fatal_mitm();

    // Read two values from data slots
    uint32_t lastgood=0, match_count=0, counter=0;
    if(_read_slot_as_counter(KEYNUM_lastgood, &lastgood)) return -1;
    if(_read_slot_as_counter(KEYNUM_match_count, &match_count)) return -1;

    // Read the monotonically-increasing counter
    if(ae_get_counter(&counter, 0, false)) return -1;

    // Do the math
    if(lastgood > counter) {
        // monkey business, but impossible, right?!
        args->num_fails = 99;
    } else {
        args->num_fails = counter - lastgood;
    }

    uint32_t mc = (match_count & ~31);
    if(counter < mc) {
        args->attempts_left = mc - counter;
    } else {
        // we're a brick now, but maybe say that nicer to customer
        args->attempts_left = 0;
    }

    return 0;
}

// warmup_ae()
//
    static int
warmup_ae(void)
{
    ae_setup();

    for(int retry=0; retry<5; retry++) {
        if(!ae_probe()) break;
    }

    if(ae_pair_unlock()) return -1;

    // reset watchdog timer
    ae_keep_alive();

    return 0;
}

// calc_delay_required()
//
    uint32_t
calc_delay_required(int num_fails)
{
    // With the 608a, we let the slow KDF and the auto counter incr
    // protect against rate limiting... no need to do our own.
    return 0;
}

// maybe_brick_myself()
//
// Attempt the provided pin against the "brickme" slot, and if it
// works, immediately destroy the pairing secret so that we become
// a useless brick.
//
    static int
maybe_brick_myself(const char *pin, int pin_len)
{
    uint8_t     digest[32];
    int         rv = 0;

    if(!pin_len) return 0;

    pin_hash(pin, pin_len, digest, PIN_PURPOSE_NORMAL);

    ae_reset_chip();
    rv = ae_pair_unlock();
    if(rv) return rv;

    // Concern: MitM could block this by trashing our write
    // - but they have to do it without causing CRC or other comm error

    if(ae_checkmac(KEYNUM_brickme, digest) == 0) {
        // success... kinda: brick time.
        ae_destroy_key(KEYNUM_pairing);

        rv = 1;
    }

    ae_reset_chip();

    return rv;
}

// pin_setup_attempt()
//
// Get number of failed attempts on a PIN, since last success. Calculate
// required delay, and setup initial struct for later attempts.
//
    int
pin_setup_attempt(pinAttempt_t *args)
{
    STATIC_ASSERT(sizeof(pinAttempt_t) == PIN_ATTEMPT_SIZE_V2);

    int rv = _validate_attempt(args, true);
    if(rv) return rv;

    // NOTE: Can only attempt primary and secondary pins. If it happens to
    // match duress or brickme pins, then perhaps something happens,
    // but not allowed to test for those cases even existing.

    if(args->is_secondary) {
        // secondary PIN feature has been removed, might be old main firmware tho
        return EPIN_PRIMARY_ONLY;
    }

    // wipe most of struct, keep only what we expect and want!
    // - old firmware wrote zero to magic before this point, and so we set it here
    uint32_t given_magic = args->magic_value;
    bool    old_firmware = (given_magic != PA_MAGIC_V2);

    char    pin_copy[MAX_PIN_LEN];
    int     pin_len = args->pin_len;
    memcpy(pin_copy, args->pin, pin_len);

    memset(args, 0, old_firmware ? PIN_ATTEMPT_SIZE_V1 : PIN_ATTEMPT_SIZE_V2);

    // indicate our policies will be different from Mark 1/2
    args->state_flags = PA_HAS_608A;

    args->magic_value = given_magic?:PA_MAGIC_V1;
    args->pin_len = pin_len;
    memcpy(args->pin, pin_copy, pin_len);

    // unlock the AE chip
    if(warmup_ae()) {
        return EPIN_I_AM_BRICK;
    }

    if(args->pin_len) {
        // Implement the brickme feature here, nice and early: Immediate brickage if
        // provided PIN matches that special PIN.
        if(maybe_brick_myself(args->pin, args->pin_len)) {
            return EPIN_I_AM_BRICK;
        }
    }

    // read counters, and calc number of PIN attempts left
    if(get_last_success(args)) {
        ae_reset_chip();

        return EPIN_AE_FAIL;
    }

    // has the duress pin (this wallet) been used this power cycle?
    uint32_t fake_lastgood = backup_data_get(IDX_DURESS_USED);
    if(fake_lastgood) {
        // lie about # of failures, but keep the pin-rate limiting
        args->num_fails = 0;
        args->attempts_left = MIN_TARGET_ATTEMPTS;
    }

    // delays now handled by chip and our KDF process directly
    args->delay_required = 0;
    args->delay_achieved = 0;

    // need to know if we are blank/unused device
    if(pin_is_blank(KEYNUM_main_pin)) {
        args->state_flags |= PA_SUCCESSFUL | PA_IS_BLANK;
    }

    _sign_attempt(args);

    return 0;
}

// pin_delay()
//
// Delay for one time unit, and prove it. Doesn't check PIN value itself.
//
    int
pin_delay(pinAttempt_t *args)
{
    // not required for 608a case, shouldn't be called
#if 0
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    // prevent any monkey business w/ systick rate
    // - we don't use interrupts, but this code is called after mpy starts sometimes,
    //   and in those cases, we want to keep their interrupt support working.
    uint32_t b4 = SysTick->CTRL;
    systick_setup();
    SysTick->CTRL |= (b4 & SysTick_CTRL_TICKINT_Msk);

    delay_ms(500);

    args->delay_achieved += 1;

    _sign_attempt(args);
#endif

    return 0;
}

// updates_for_good_login()
//
    static int
updates_for_good_login(pinAttempt_t *args, uint8_t digest[32])
{
    // User got the main PIN right: update the attempt counters,
    // to document this (lastgood) and also bump the match counter if needed

    uint32_t new_count;
    int rv = ae_get_counter(&new_count, 0, true);
    if(rv) return EPIN_AE_FAIL;

    // update the "last good" counter
    uint32_t    tmp[32/4] = {0};
    tmp[0] = new_count;

    rv = ae_encrypted_write(KEYNUM_lastgood, KEYNUM_main_pin, digest, (void *)tmp, 32);
    if(rv) {
        ae_reset_chip();
        return EPIN_AE_FAIL;
    }

    uint32_t mc = (new_count + MIN_TARGET_ATTEMPTS) & ~31;
    tmp[0] = tmp[1] = mc;

    rv = ae_encrypted_write(KEYNUM_match_count, KEYNUM_main_pin, digest, (void *)tmp, 32);
    if(rv) {
        ae_reset_chip();
        return EPIN_AE_FAIL;
    }

    args->num_fails = 0;
    args->attempts_left = mc - new_count;

    // NOTE: Some of the above writes could be blocked (trashed) by an
    // active MitM attacker, but that would be pointless since these are authenticated
    // writes, which have a MAC. They can't change the written value nor the MAC, so
    // all they can do is block the write, and not control it's value. So, they will
    // just be reducing tries. Also, rate limiting not affected but anything here.

    return 0;
}

// pin_cache_save()
//
    static void
pin_cache_save(pinAttempt_t *args, const uint8_t digest[32])
{
    if(args->magic_value == PA_MAGIC_V2) {
        memcpy(args->cached_main_pin, digest, 32);
    } else {
        // short-term hack .. only applies if old firmware (not v3+) is used on
        // mark3 hardware.
        memcpy(transitional_pinhash_cache, digest, 32);
    }
}

// pin_cache_restore()
//
    static void
pin_cache_restore(pinAttempt_t *args, uint8_t digest[32])
{
    if(args->magic_value == PA_MAGIC_V2) {
        memcpy(digest, args->cached_main_pin, 32);
    } else {
        // short-term hack .. only applies if old firmware (not v3+) is used on
        // mark3 hardware.
        memcpy(digest, transitional_pinhash_cache, 32);
    }
}


// pin_login_attempt()
//
// Do the PIN check, and return a value. Or fail.
//
    int
pin_login_attempt(pinAttempt_t *args)
{
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    // OBSOLETE: did they wait long enough?
    // if(args->delay_achieved < args->delay_required) return EPIN_MUST_WAIT;

    if(args->state_flags & PA_SUCCESSFUL) {
        // already worked, or is blank
        return EPIN_WRONG_SUCCESS;
    }

    // unlock the AE chip
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    int pin_kn = -1;
    bool is_duress = false;
    int secret_kn = -1;

    // hash up the pin now, assuming we'll use it on main PIN
    uint8_t     digest[32];
    rv = pin_hash_attempt(KEYNUM_main_pin, args->pin, args->pin_len, digest);
    if(rv) return EPIN_AE_FAIL;

    // .. but first check if it's a the duress pin
    if(is_duress_pin(digest, (args->pin_len == 0), &pin_kn)) {
        // they gave the duress PIN for this wallet... try to continue w/o any indication
        is_duress = true;

        secret_kn = KEYNUM_duress_secret;

        // for next run, we need to pretend like no failures (a little -- imperfect)
        backup_data_set(IDX_DURESS_USED, 1);
    } else {
        // Assume it's the real PIN, and register as an attempt on that.

        if(!is_main_pin(digest, &pin_kn)) {
            // PIN code is just wrong.
            // - nothing to update, since the chip's done it already
            return EPIN_AUTH_FAIL;
        }

        secret_kn = KEYNUM_secret;

        // change the various counters, since this worked
        rv = updates_for_good_login(args, digest);
        if(rv) return EPIN_AE_FAIL;
    }

    // SUCCESS! "digest" holds a working value. Save it.
    pin_cache_save(args, digest);

    // update flag about duress and weakly hide in some chaff
    args->private_state = (rng_sample() & ~1) | is_duress;

    // ASIDE: even if the above was bypassed, the following code will
    // fail when it tries to read/update the corresponding slots in the SE

    // mark as success
    args->state_flags = PA_SUCCESSFUL;

    // I used to always read the secret, since it's so hard to get to this point,
    // but now just indicating if zero or non-zero so that we don't contaminate the
    // caller w/ sensitive data that they may not want yet.
    {   uint8_t ts[AE_SECRET_LEN];

        rv = ae_encrypted_read(secret_kn, pin_kn, digest, ts, AE_SECRET_LEN);
        if(rv) {
            ae_reset_chip();

            return EPIN_AE_FAIL;
        }
        ae_reset_chip();

        if(check_all_zeros(ts, AE_SECRET_LEN)) {
            args->state_flags |= PA_ZERO_SECRET;
        }
    }

    // indicate what features already enabled/non-blank
    if(is_duress) {
        // provide false answers to status of duress and brickme
        args->state_flags |= (PA_HAS_DURESS | PA_HAS_BRICKME);
    } else {
        // do we have duress password?
        if(!pin_is_blank(KEYNUM_duress_pin)) {
            args->state_flags |= PA_HAS_DURESS;
        }

        // do we have brickme set?
        if(!pin_is_blank(KEYNUM_brickme)) {
            args->state_flags |= PA_HAS_BRICKME;
        }
    }

    // In mark1/2, was thinking of maybe storing duress flag into private state,
    // but no real need, but testing for it's expensive in mark3, so going to use
    // LSB here for that.
    args->private_state = rng_sample() & ~1;

    _sign_attempt(args);

    return 0;
}

// pin_change()
//
// Change the PIN and/or secrets (must also know the value, or it must be blank)
//
    int
pin_change(pinAttempt_t *args)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }

    if(args->state_flags & PA_IS_BLANK) {
        // if blank, must provide blank value
        if(args->pin_len) return EPIN_RANGE_ERR;
    }

    // Look at change flags.

    const uint32_t cf = args->change_flags;

    // obsolete secondary support
    ASSERT(!args->is_secondary);
    if(cf & CHANGE_SECONDARY_WALLET_PIN) {
        return EPIN_BAD_REQUEST;
    }

    // must be here to do something.
    if(cf == 0) return EPIN_RANGE_ERR;

    if(cf & CHANGE_BRICKME_PIN) {
        if(cf != CHANGE_BRICKME_PIN) {
            // only pin can be changed, nothing else.
            return EPIN_BAD_REQUEST;
        }
    }
    if((cf & CHANGE_DURESS_SECRET) && (cf & CHANGE_SECRET)) {
        // can't change two secrets at once.
        return EPIN_BAD_REQUEST;
    }

    // ASIDE: Can always change a PIN you already know
    // but can only prove you know the primary/secondary
    // pin up to this point ... none of the others.
    // That's why we need old_pin fields.

    // Restore cached version of PIN digest
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // unlock the AE chip
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // If they authorized w/ the duress password, we let them
    // change it (the duress one) while they think they are changing
    // the main one. Always pretend like the duress wallet is already enabled.
    // But if they try to change duress wallet PIN, we can't actually work.
    // Same for brickme PIN.

    // SO ... we need to know if they started w/ a duress wallet.

    // what pin got us here? (ie. in 'digest' already)
    int pin_kn = -1;
    // what pin do they need to know to make their change?
    int required_kn = -1;
    // what slot (key number) are updating?
    int target_slot = -1;

    bool is_duress = (args->private_state & 0x1);

    if(is_duress) {
        // user is a thug.. limit what they can do

        // check for brickme pin on everything here.
        if(maybe_brick_myself(args->old_pin, args->old_pin_len)
                || maybe_brick_myself(args->new_pin, args->new_pin_len)
        ) {
            return EPIN_I_AM_BRICK;
        }

        if((cf & CHANGE_WALLET_PIN) != cf) {
            // trying to do anything but change PIN must fail.
            ae_reset_chip();

            return EPIN_OLD_AUTH_FAIL;
        }

        pin_kn = required_kn = target_slot = KEYNUM_duress_pin;
    } else {
        // No need to re-prove PIN knowledge.
        // If they tricked us, doesn't matter as below the SE validates it all again.
        pin_kn = required_kn = KEYNUM_main_pin;

        if(cf & CHANGE_WALLET_PIN) {
            target_slot = KEYNUM_main_pin;
        } else if(cf & CHANGE_SECRET) {
            target_slot = KEYNUM_secret;
        } else if(cf & CHANGE_DURESS_PIN) {
            required_kn = KEYNUM_duress_pin;
            target_slot = KEYNUM_duress_pin;
        } else if(cf & CHANGE_DURESS_SECRET) {
            required_kn = KEYNUM_duress_pin;
            target_slot = KEYNUM_duress_secret;
        } else if(cf & CHANGE_BRICKME_PIN) {
            required_kn = KEYNUM_main_pin;
            target_slot = KEYNUM_brickme;
        } else {
            return EPIN_RANGE_ERR;
        }
    }

    // Determine they known hash protecting the secret/pin to be changed.
    uint8_t required_digest[32]; 
    if(required_kn != pin_kn) {
        pin_hash_attempt(required_kn, args->old_pin, args->old_pin_len, required_digest);

        // Check the old pin is right.
        ae_pair_unlock();
        if(ae_checkmac(required_kn, required_digest)) {
            // they got old PIN wrong, we won't be able to help them
            ae_reset_chip();

            // NOTE: altho we are changing flow based on result of ae_checkmac() here,
            // if the response is faked by an active bus attacker, it doesn't matter
            // because the change to the keyslot below will fail due to wrong PIN.

            return EPIN_OLD_AUTH_FAIL;
        }
    } else {
        memcpy(required_digest, digest, 32);
    }

    // Record new PIN value.
    if(cf & (CHANGE_WALLET_PIN | CHANGE_DURESS_PIN | CHANGE_BRICKME_PIN)) {
        // First calculate new PIN hased value.

        uint8_t new_digest[32]; 
        rv = pin_hash_attempt(target_slot, args->new_pin, args->new_pin_len, new_digest);
        if(rv) goto ae_fail;

        if(ae_encrypted_write(target_slot, required_kn, required_digest, new_digest, 32)) {
            goto ae_fail;
        }

        if(target_slot == required_kn) {
            memcpy(required_digest, new_digest, 32);
        }
        if(target_slot == KEYNUM_main_pin) {
            pin_cache_save(args, new_digest);

            updates_for_good_login(args, new_digest);
        }
    }

    // Record new secret.
    // Note the digest might have just changed above.
    if(cf & (CHANGE_SECRET | CHANGE_DURESS_SECRET)) {
        int secret_kn = (required_kn == KEYNUM_main_pin) ? KEYNUM_secret : KEYNUM_duress_secret;

        if(ae_encrypted_write(secret_kn, required_kn,
                                        required_digest, args->secret, AE_SECRET_LEN)){
            goto ae_fail;
        }

        // update the zero-secret flag to be correct.
        if(cf & CHANGE_SECRET) {
            if(check_all_zeros(args->secret, AE_SECRET_LEN)) {
                args->state_flags |= PA_ZERO_SECRET;
            } else {
                args->state_flags &= ~PA_ZERO_SECRET;
            }
        }
    }

    ae_reset_chip();

    // need to pass back the (potentially) updated cache value and some flags.
    _sign_attempt(args);

    return 0;

ae_fail:
    ae_reset_chip();

    return EPIN_AE_FAIL;
}

// pin_fetch_secret()
//
// To encourage not keeping the secret in memory, a way to fetch it after already
// have proven you know the PIN.
//
    int
pin_fetch_secret(pinAttempt_t *args)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }

    // fetch the already-hashed pin
    // - no real need to re-prove PIN knowledge.
    // - if they tricked us, doesn't matter as below the SE validates it all again
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // try it out / and determine if we should proceed under duress
    bool is_duress = (args->private_state & 0x1);

    int pin_kn = is_duress ? KEYNUM_duress_pin : KEYNUM_main_pin;
    int secret_slot = is_duress ? KEYNUM_duress_secret : KEYNUM_secret;

    if(args->change_flags & CHANGE_DURESS_SECRET) {
        // Let them know the duress secret, iff: 
        // - they are logged into corresponding primary pin (not duress) 
        // - and they know the duress pin as well.
        // LATER: this feature not being used since we only write the duress secret
        if(is_duress) return EPIN_AUTH_FAIL;

        pin_kn = KEYNUM_duress_pin;
        secret_slot = KEYNUM_duress_secret;

        rv = pin_hash_attempt(pin_kn, args->old_pin, args->old_pin_len, digest);
        if(rv) goto fail;

        // Check the that pin is right (optional, but if wrong, encrypted read gives garb)
        ae_pair_unlock();
        if(ae_checkmac(pin_kn, digest)) {
            // They got old duress PIN wrong, we won't be able to help them.
            ae_reset_chip();

            // NOTE: altho we are changing flow based on result of ae_checkmac() here,
            // if the response is faked by an active bus attacker, it doesn't matter
            // because the decryption of the secret below will fail if we had been lied to.
            return EPIN_AUTH_FAIL;
        }
    }

    // read out the secret that corresponds to that pin
    rv = ae_encrypted_read(secret_slot, pin_kn, digest, args->secret, AE_SECRET_LEN);

fail:
    ae_reset_chip();

    if(rv) return EPIN_AE_FAIL;

    return 0;
}

// pin_firmware_greenlight()
//
// Record current flash checksum and make green light go on.
//
    int
pin_firmware_greenlight(pinAttempt_t *args)
{
    // Validate args and signature
    int rv = _validate_attempt(args, false);
    if(rv) return rv;

    if((args->state_flags & PA_SUCCESSFUL) != PA_SUCCESSFUL) {
        // must come here with a successful PIN login (so it's rate limited nicely)
        return EPIN_WRONG_SUCCESS;
    }

    if(args->is_secondary) {
        // only main PIN holder can do this
        return EPIN_PRIMARY_ONLY;
    }

    // load existing PIN's hash
    uint8_t     digest[32];
    pin_cache_restore(args, digest);

    // step 1: calc the value to use
    uint8_t fw_check[32], world_check[32];
    checksum_flash(fw_check, world_check);

    // step 2: write it out to chip.
    if(warmup_ae()) return EPIN_I_AM_BRICK;

    // under duress, we can't fake this, but we go through the motions,
    bool is_duress = (args->private_state & 0x1);
    if(!is_duress) {
        rv = ae_encrypted_write(KEYNUM_firmware, KEYNUM_main_pin, digest, world_check, 32);

        if(rv) {
            ae_reset_chip();

            return EPIN_AE_FAIL;
        }
    }

    // turn on light
    rv = ae_set_gpio_secure(world_check);
    if(rv) {
        ae_reset_chip();

        return EPIN_AE_FAIL;
    }

    return 0;
}


// EOF
