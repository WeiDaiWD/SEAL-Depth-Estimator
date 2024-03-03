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
    if (scheme == scheme_type::bfv)
    {
        evaluator.mod_switch_to_next_inplace(ct);
    }
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
        if (scheme == scheme_type::bfv)
        {
            evaluator.mod_switch_to_next_inplace(ct);
        }
        budget = decryptor.invariant_noise_budget(ct);
    }

    return capability;
}

static void print_test(size_t poly_modulus_degree, int plain_modulus_bit_size, const vector<int> &coeff_modulus_bit_sizes, scheme_type scheme = scheme_type::bfv)
{
    cout << "( " << poly_modulus_degree << ", " << plain_modulus_bit_size << ", {";
    for (size_t i = 0; i < coeff_modulus_bit_sizes.size(); i++)
    {
        cout << coeff_modulus_bit_sizes[i];
        if (i != coeff_modulus_bit_sizes.size() - 1)
        {
            cout << ", ";
        }
    }
    cout << "} )\t";
    Capability capability = estimate(poly_modulus_degree, plain_modulus_bit_size, coeff_modulus_bit_sizes, scheme);
    cout << "maximum depth: " << capability.max_depth << ", noise budget left: " << capability.budget_bits << " bits" << endl;
}

int main()
{
    print_test(32768, 20, {60, 30, 30, 52, 50, 56, 60, 60, 60, 60, 60, 60, 60, 60, 60}, scheme_type::bgv); //L = 21

    return 0;
}