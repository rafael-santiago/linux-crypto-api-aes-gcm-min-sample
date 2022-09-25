/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/internal/aead.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

// 'A good idea is an orphan without effective communication'...

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,18)
// WARN(Rafael): I have tested it on 4.4.14 and this workaround seems fine
//               on my tests. Anyway, if you are gonna to use it you should
//               question someone more near to linux/crypto subtree about it.
//               Maybe it can be capable of causing some unrelated unstability
//               in the system as whole, but only who actually work with the
//               crypto core would say.

struct crypto_wait {
    struct completion completion;
    int err;
};

void crypto_req_done(struct crypto_async_request *req, int err) {
    struct crypto_wait *wait = req->data;

    if (err == -EINPROGRESS)
        return;

    wait->err = err;
    complete(&wait->completion);
}

EXPORT_SYMBOL_GPL(crypto_req_done);

static inline int crypto_wait_req(int err, struct crypto_wait *wait) {
    switch (err) {
    case -EINPROGRESS:
    case -EBUSY:
        wait_for_completion(&wait->completion);
        reinit_completion(&wait->completion);
        err = wait->err;
        break;
    }

    return err;
}

#define DECLARE_CRYPTO_WAIT(_wait) \
    struct crypto_wait _wait = {\
        COMPLETION_INITIALIZER_ONSTACK((_wait).completion) }

#endif // LINUX_VERSION_CODE < KERNEL_VERSION(4,15,18)

MODULE_AUTHOR("Rafael Santiago");
MODULE_DESCRIPTION("aes-gcm-min-sample is an attempt of producing a sane and well-explained "
                   "tiny code to show how to use (minimally) AES-256/GCM into with Linux "
                   "kernel crypto API. Instead of wasting hours grasping into code that "
                   "does not matter directly to your task. "
                   "Issues <https://github.com/rafael-santiago/linux-crypto-api-aes-gcm-min-sample/issues>, thank you!");
MODULE_LICENSE("GPL");

#define TEST_DATA "This is a test!!"
#define TEST_DATA_SIZE 16
#define AES_GCM_TAG_SIZE 16

int do_aes_gcm_min_sample(void) {
    struct crypto_aead *tfm = NULL;
    struct aead_request *req = NULL;
    u8 *buffer = NULL;
    size_t buffer_size = TEST_DATA_SIZE;
    u8 *bp = NULL, *bp_end = NULL;
    struct scatterlist sg = { 0 };
    DECLARE_CRYPTO_WAIT(wait);
    // INFO(Rafael): The majority of AES/GCM implementation uses 12 bytes iv (crypto_aead_ivsize()
    //               returns this, so for this reason I am using this "magic" value here.)
    u8 iv[12] = { 0 };
    u8 key[32] = { 0 }; // INFO(Rafael): The version of AES is defined by the size (in bytes) of the
                        //               informed key. So, here we are using AES-256.
    int err = -1;

    tfm = crypto_alloc_aead("gcm(aes)", 0, 0);

    if (IS_ERR(tfm)) {
        err = PTR_ERR(tfm);
        pr_err("AES/GCM min sample: crypto_alloc_aead() has failed: %d.\n", err);
        goto do_aes_gcm_min_sample_epilogue;
    }

    // INFO(Rafael): Telling to API how many bytes will compound our MAC (a.k.a tag etc [etc no!...]).
    err = crypto_aead_setauthsize(tfm, AES_GCM_TAG_SIZE);
    if (err != 0) {
        pr_err("AES/GCM min sample: crypto_aead_setauthsize() has failed: %d.\n", err);
        goto do_aes_gcm_min_sample_epilogue;
    }

    // WARN(Rafael): In practice it could come from a `KDF(weak_usr_password)` stuff.
    //               Never ever use directly the "key" informed by the user.
    //               It demolishes the good will of any crypto algorithm on
    //               doing good encryption. Let's value hard work of cryptographers on
    //               seeking to create state of the art ciphers ;), please!
    //               So, I am only getting the key from a csprng that is a thing
    //               near to what an alleged good KDF is able to do with a weak password
    //               or at least must do.
    get_random_bytes(key, sizeof(key));
    err = crypto_aead_setkey(tfm, key, sizeof(key));
    if (err != 0) {
        pr_err("AES/GCM min sample: crypto_aead_setkey() has failed: %d.\n", err);
        goto do_aes_gcm_min_sample_epilogue;
    }

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (req == NULL) {
        err = -ENOMEM;
        pr_err("AES/GCM min sample: aead_request_alloc() has failed.\n");
        goto do_aes_gcm_min_sample_epilogue;
    }
    req->assoclen = 0; // INFO(Rafael): No associated data, just reinforcing it.
                       //               Anyway, when you want to also authenticated
                       //               plain data (a.k.a AAD, associated data) you
                       //               must indicate the size in bytes of the aad
                       //               here and prepend your plaintext with aad.

    get_random_bytes(iv, sizeof(iv));

    // INFO(Rafael): The AES/GCM encryption primitive will also spit at the end of
    //               the encrypted buffer the n bytes asked tags generated by GHASH.
    //               Since we are using the same buffer for output stuff, this buffer
    //               must be able to fit the input and ***also*** the result.
    buffer_size = TEST_DATA_SIZE + AES_GCM_TAG_SIZE;
    buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (buffer == NULL) {
        err = -ENOMEM;
        pr_err("AES/GCM min sample: kmalloc() has failed.\n");
        goto do_aes_gcm_min_sample_epilogue;
    }

    // INFO(Rafael): Copying the one block input...
    memcpy(buffer, TEST_DATA, TEST_DATA_SIZE);
    bp = buffer;
    bp_end = bp + TEST_DATA_SIZE;

    // INFO(Rafael): Currently buffer contains only one dummy test block. Right?...
    pr_info("Original data: ");
    while (bp != bp_end) {
        pr_info("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    // INFO(Rafael): ...however our scattterlist must be initialised
    //               by indicating the whole allocated buffer segment (including room
    //               for the tag). Because it will also output data, got it?
    sg_init_one(&sg, buffer, buffer_size);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                   CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);

    // INFO(Rafael): Thus, for ***encrypting*** our input buffer is
    //                      `TEST_DATA_SIZE == buffer_size - AES_GCM_TAG_SIZE`,
    //               since
    //                      `buffer_size == TEST_DATA_SIZE + AES_GCM_TAG_SIZE`.
    aead_request_set_crypt(req, &sg, &sg, buffer_size - AES_GCM_TAG_SIZE, iv);
    err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
    if (err != 0) {
        pr_err("AES/GCM min sample: error when encrypting data: %d.\n", err);
        goto do_aes_gcm_min_sample_epilogue;
    }

    // INFO(Rafael): If aad would be also passed it would prepend the cryptogram.
    //               req-assoclen give you the clue of how much traversing or even how much bytes
    //               ahead must be skipped.

    pr_info("Cryptogram: ");
    // INFO(Rafael): Now buffer contains the authenticated cryptogram. I meant <cryptogram><MAC>.
    //               Here the intention is only printing the cryptogram.
    bp = buffer;
    bp_end = bp + buffer_size - AES_GCM_TAG_SIZE;
    while (bp != bp_end) {
        pr_info("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    pr_info("Authentication tag: ");
    // INFO(Rafael): Since bp is already pointing to the first byte of what should be the tag, let's only moving
    //               AES_GCM_TAG_SIZE bytes ahead the end marker of the output buffer.
    bp_end += AES_GCM_TAG_SIZE;
    while (bp != bp_end) {
        pr_info("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }

    // INFO(Rafael): I hate incomplete samples, so let's decrypt, too.
    //               Decrypting with GCM involves check whether the tag informed at the end of cryptogram
    //               is really the same of the on-the-fly calculated by GHASH. Thus, when decrypting the
    //               is necessary to indicate the cryptogram and ***also*** the tag, so here its size is
    //               expressed by buffer_size.
    aead_request_set_crypt(req, &sg, &sg, buffer_size, iv);


    // INFO(Rafael): What about testing if GCM is really detecting tampered data?
    //               Give it a try by uncomment all or even one of the following three lines.
    //key[sizeof(key) >> 1] += 1;
    //buffer[buffer_size >> 1] += 1;
    //buffer[buffer_size - AES_GCM_TAG_SIZE + 1] += 1; // INFO(Rafael): MAC bit flipping.

    // INFO(Rafael): For the context of this sample, it would not be necessary. Anyway, we want to test
    //               corrupted key cases.
    err = crypto_aead_setkey(tfm, key, sizeof(key));
    if (err != 0) {
        pr_err("AES/GCM min sample: crypto_aead_setkey() has failed: %d.\n", err);
        goto do_aes_gcm_min_sample_epilogue;
    }

    err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
    if (err != 0) {
        pr_err("AES/GCM min sample: Error when decrypting data, it seems tampered. "
               "Ask for a retransmission or verify your key.\n");
        goto do_aes_gcm_min_sample_epilogue;
    }

    // INFO(Rafael): If aad would be also passed it would prepend the plaintext.
    //               req->assoclen give you the clues of how to traverse or even
    //               skipping it. But even skipped it must be passed by the
    //               decryption routine. Because it also authenticates the whole
    //               buffer, got it?

    pr_info("Authenticated plaintext: ");
    bp = buffer;
    bp_end = bp + buffer_size - AES_GCM_TAG_SIZE; // INFO(Rafael): It will not reallocate the buffer so, let's exclude the MAC.
                                                  //               Due to it maybe should be good to ensure a buffer_size multiple of four.
                                                  //               It would keep this simpler. Anyway you can apply a more sophisticated
                                                  //               padding technique, but for this sample I think it express the main idea.
    while (bp != bp_end) {
        pr_info("%c\n", isprint(*bp) ? *bp : '.');
        bp++;
    }


do_aes_gcm_min_sample_epilogue:

    if (req != NULL) {
        aead_request_free(req);
    }

    if (tfm != NULL) {
        crypto_free_aead(tfm);
    }

    if (buffer != NULL) {
        kfree(buffer);
    }

    return err;
}

int __init init_aes_gcm_min_sample(void) {
    pr_info("AES/GCM minimal sample: Running.\n");
    return do_aes_gcm_min_sample();
}

void __exit deinit_aes_gcm_min_sample(void) {
    pr_info("AES/GCM minimal sample: Finished.\n");
}

module_init(init_aes_gcm_min_sample);
module_exit(deinit_aes_gcm_min_sample);

#undef TEST_DATA
#undef TEST_DATA_SIZE
#undef AES_GCM_TAG_SIZE
