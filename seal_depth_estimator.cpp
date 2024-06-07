// Copyright (c) Wei Dai (weidai3141@gmail.com). All rights reserved.
// Licensed under the MIT license.

#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

struct Parameters
{
    size_t poly_modulus_degree;
    int plain_modulus_bit_size;
    const vector<int> &coeff_modulus_bit_sizes;
};

struct Capability
{
    int max_depth;
    int budget_bits;
};

static Capability estimate(size_t poly_modulus_degree, int plain_modulus_bit_size, const vector<int> &coeff_modulus_bit_sizes, scheme_type scheme = scheme_type::bfv)
{
    Capability capability;
    // If max_depth is -1, decryption of a fresh ciphertext fails.
    capability.max_depth = -1;
    capability.budget_bits = 0;

    EncryptionParameters parms(scheme);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    try
    {
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, plain_modulus_bit_size));
    }
    catch (...)
    {
        cout << "Error: cannot find a plain_modulus for the bit size\t";
        return capability;
    }
    try
    {
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, coeff_modulus_bit_sizes));
    }
    catch (...)
    {
        cout << "Error: cannot find enough primes for the bit sizes\t";
        return capability;
    }

    SEALContext context(parms, true, sec_level_type::none); // This disables security enforcement!

    if (!context.parameters_set())
    {
        cout << "invalid input: " << context.parameter_error_message() << endl;
    }

    KeyGenerator keygen(context);
    SecretKey sk = keygen.secret_key();
    PublicKey pk;
    keygen.create_public_key(pk);
    RelinKeys rk;
    // If coeff_modulus has only 1 prime, relinearization is disabled.
    if (coeff_modulus_bit_sizes.size() > 1)
    {
        keygen.create_relin_keys(rk);
    }
    BatchEncoder encoder(context);
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Setting n random integers modulo t as messages
    vector<uint64_t> messages(encoder.slot_count());
    for (auto &i: messages)
    {
        i = util::barrett_reduce_64((static_cast<uint64_t>(rand()) << 32) | static_cast<uint64_t>(rand()), parms.plain_modulus());
    }
    Plaintext pt;
    encoder.encode(messages, pt);
    Ciphertext ct;
    encryptor.encrypt(pt, ct);
    
    int budget = decryptor.invariant_noise_budget(ct);

    // If coeff_modulus has only 1 prime, relinearization is disabled, so is squaring.
    if (coeff_modulus_bit_sizes.size() == 1)
    {
        if (budget > 0)
        {
            capability.max_depth++;
        }
        capability.budget_bits = budget;
        return capability;
    }

    while (budget > 0)
    {
        capability.max_depth++;
        capability.budget_bits = budget;
        evaluator.square_inplace(ct);
        evaluator.relinearize_inplace(ct, rk);
        budget = decryptor.invariant_noise_budget(ct);
        if (scheme == scheme_type::bgv && budget > 0)
        {
            evaluator.mod_switch_to_next_inplace(ct);
        }
        budget = decryptor.invariant_noise_budget(ct);
    }

    return capability;
}

static void print_test(size_t poly_modulus_degree, int plain_modulus_bit_size, const vector<int> &coeff_modulus_bit_sizes, scheme_type scheme)
{
    if (scheme == scheme_type::bgv)
    {
        cout << "---BGV---" << endl;
    }
    else if (scheme == scheme_type::bfv)
    {
        cout << "---BFV---" << endl;
    }
    else
    {
        cout << "Unsupported scheme" << endl;
        return;
    }
    cout << "( " << poly_modulus_degree << ", " << plain_modulus_bit_size << ", {";
    size_t coeff_mod_prod = 0;
    for (size_t i = 0; i < coeff_modulus_bit_sizes.size(); i++)
    {
        cout << coeff_modulus_bit_sizes[i];
        coeff_mod_prod += coeff_modulus_bit_sizes[i];
        if (i != coeff_modulus_bit_sizes.size() - 1)
        {
            cout << ", ";
        }
    }
    cout << "} ), ";
    cout << "logq = "<<coeff_mod_prod<<", ";
    Capability capability = estimate(poly_modulus_degree, plain_modulus_bit_size, coeff_modulus_bit_sizes, scheme);
    cout << "maximum depth: " << capability.max_depth << ", noise budget left: " << capability.budget_bits << " bits" << endl;
}

int main()
{
    // BFV, 128-bit classic, logq = 424
    print_test(16384, 20, {53, 53, 53, 53, 53, 53, 53, 53}, scheme_type::bfv);
    // BFV, 192-bit classic, logq = 585
    print_test(32768, 20, {59, 58, 58, 58, 58, 58, 59, 59, 59, 59}, scheme_type::bfv);
    // BFV, 256-bit classic, logq = 920
    print_test(65536, 20, {58, 57, 57, 57, 57, 57, 57, 57, 57, 58, 58, 58, 58, 58, 58, 58}, scheme_type::bfv);

    // BFV, 128-bit post-quantum, logq = 391
    print_test(16384, 20, {56, 55, 56, 56, 56, 56, 56}, scheme_type::bfv);
    // BFV, 192-bit post-quantum, logq = 562
    print_test(32768, 20, {57, 56, 56, 56, 56, 56, 56, 56, 56, 57}, scheme_type::bfv);
    // BFV, 256-bit post-quantum, logq = 880
    print_test(65536, 20, {59, 58, 58, 58, 58, 58, 59, 59, 59, 59, 59, 59, 59, 59, 59}, scheme_type::bfv);

    // The following parameter choices for BGV assumes a fairly stable behavior.
    // Better parameters that support one more level in best cases may lose several leveal in corner cases.

    // BGV, 128-bit classic, logq = 424
    print_test(16384, 20, {43, 42, 42, 42, 42, 42, 42, 43, 43, 43}, scheme_type::bgv);
    // BGV, 192-bit classic, logq = 585
    print_test(32768, 20, {42, 41, 41, 41, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}, scheme_type::bgv);
    // BGV, 256-bit classic, logq = 920
    print_test(65536, 20, {44, 43, 43, 43, 43, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44}, scheme_type::bgv);

    // BGV, 128-bit post-quantum, logq = 391
    print_test(16384, 20, {44, 43, 43, 43, 43, 43, 44, 44, 44}, scheme_type::bgv);
    // BGV, 192-bit post-quantum, logq = 562
    print_test(32768, 20, {44, 43, 43, 43, 44, 44, 44, 44, 44, 44, 44, 44, 44}, scheme_type::bgv);
    // BGV, 256-bit post-quantum, logq = 880
    print_test(65536, 20, {44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44}, scheme_type::bgv);
    return 0;
}

// A printout example
// ---BFV---
// ( 16384, 20, {53, 53, 53, 53, 53, 53, 53, 53} ), logq = 424, maximum depth: 10, noise budget left: 8 bits
// ---BFV---
// ( 32768, 20, {59, 58, 58, 58, 58, 58, 59, 59, 59, 59} ), logq = 585, maximum depth: 14, noise budget left: 14 bits
// ---BFV---
// ( 65536, 20, {58, 57, 57, 57, 57, 57, 57, 57, 57, 58, 58, 58, 58, 58, 58, 58} ), logq = 920, maximum depth: 23, noise budget left: 9 bits
// ---BFV---
// ( 16384, 20, {56, 55, 56, 56, 56, 56, 56} ), logq = 391, maximum depth: 9, noise budget left: 6 bits
// ---BFV---
// ( 32768, 20, {57, 56, 56, 56, 56, 56, 56, 56, 56, 57} ), logq = 562, maximum depth: 13, noise budget left: 28 bits
// ---BFV---
// ( 65536, 20, {59, 58, 58, 58, 58, 58, 59, 59, 59, 59, 59, 59, 59, 59, 59} ), logq = 880, maximum depth: 22, noise budget left: 7 bits
// ---BGV---
// ( 16384, 20, {43, 42, 42, 42, 42, 42, 42, 43, 43, 43} ), logq = 424, maximum depth: 8, noise budget left: 14 bits
// ---BGV---
// ( 32768, 20, {42, 41, 41, 41, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42} ), logq = 585, maximum depth: 12, noise budget left: 13 bits
// ---BGV---
// ( 65536, 20, {44, 43, 43, 43, 43, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44} ), logq = 920, maximum depth: 19, noise budget left: 14 bits
// ---BGV---
// ( 16384, 20, {44, 43, 43, 43, 43, 43, 44, 44, 44} ), logq = 391, maximum depth: 7, noise budget left: 15 bits
// ---BGV---
// ( 32768, 20, {44, 43, 43, 43, 44, 44, 44, 44, 44, 44, 44, 44, 44} ), logq = 569, maximum depth: 11, noise budget left: 15 bits
// ---BGV---
// ( 65536, 20, {44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 44} ), logq = 880, maximum depth: 18, noise budget left: 14 bits