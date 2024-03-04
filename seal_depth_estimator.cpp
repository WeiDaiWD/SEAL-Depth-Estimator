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
    Ciphertext ct, ct_0;
    encryptor.encrypt(pt, ct);
    encryptor.encrypt(pt, ct_0);
    
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
        evaluator.multiply_inplace(ct, ct_0);
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
    if (scheme == scheme_type::bgv){
        cout << "---BGV---" << endl;
    }else{
        cout << "---BFV---" << endl;
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
    cout << "} )\t";
    cout << "(logq = "<<coeff_mod_prod<<") "; 
    Capability capability = estimate(poly_modulus_degree, plain_modulus_bit_size, coeff_modulus_bit_sizes, scheme);
    cout << "maximum depth: " << capability.max_depth << ", noise budget left: " << capability.budget_bits << " bits" << endl;
}

int main()
{
    print_test(16384, 20, {59, 59, 45, 59, 59, 24, 59, 60}, scheme_type::bfv);// L = 10, logq = 424
    print_test(16384, 20, {59, 59, 36, 59, 59, 59, 60}, scheme_type::bfv); //L = 9, logq = 391
    print_test(32768, 20, {60, 30, 30, 50, 55, 60, 60, 60, 60, 60, 60}, scheme_type::bfv); //L = 14, logq = 585
    print_test(32768, 20, {60, 30, 30, 50, 52, 50, 50, 60, 60, 60, 60}, scheme_type::bfv); //L = 13, logq = 572
    print_test(65536, 20, {60, 58, 50, 50, 52, 50, 60, 60, 60, 60, 60, 60,  60, 60, 60, 60}, scheme_type::bfv); //L =  23, logq = 920
    print_test(65536, 20, {60, 58, 40, 50, 52, 50, 30, 60, 60, 60, 60, 60,  60, 60, 60, 60}, scheme_type::bfv); //L = 22, logq = 880

    print_test(16384, 20, {59, 59, 45, 59, 59, 24, 59, 60}, scheme_type::bgv);// L = 5, logq = 424
    print_test(16384, 20, {59, 59, 36, 59, 59, 59, 60}, scheme_type::bgv); //L = 4, logq = 391
    print_test(32768, 20, {60, 30, 30, 50, 55, 60, 60, 60, 60, 60, 60}, scheme_type::bgv); //L = 8, logq = 585
    print_test(32768, 20, {60, 30, 30, 50, 52, 50, 50, 60, 60, 60, 60}, scheme_type::bgv); //L = 7, logq = 572
    print_test(65536, 20, {60, 58, 50, 50, 52, 50, 60, 60, 60, 60, 60, 60,  60, 60, 60, 60}, scheme_type::bgv); //L = 13, logq = 920 
    print_test(65536, 20, {60, 58, 40, 50, 52, 50, 30, 60, 60, 60, 60, 60,  60, 60, 60, 60}, scheme_type::bgv); //L = 12, logq = 880
    return 0;
}
// A printout example
// ---BFV---
// ( 16384, 20, {59, 59, 45, 59, 59, 24, 59, 60} ) (logq = 424) maximum depth: 10, noise budget left: 1 bits
// ---BFV---
// ( 16384, 20, {59, 59, 36, 59, 59, 59, 60} )     (logq = 391) maximum depth: 9, noise budget left: 1 bits
// ---BFV---
// ( 32768, 20, {60, 30, 30, 50, 55, 60, 60, 60, 60, 60, 60} )     (logq = 585) maximum depth: 14, noise budget left: 12 bits
// ---BFV---
// ( 32768, 20, {60, 30, 30, 50, 52, 50, 60, 60, 60, 60, 60} )     (logq = 572) maximum depth: 13, noise budget left: 33 bits
// ---BFV---
// ( 65536, 20, {60, 58, 50, 50, 52, 50, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60} ) (logq = 920) maximum depth: 23, noise budget left: 13 bits
// ---BFV---
// ( 65536, 20, {60, 58, 40, 50, 52, 50, 30, 60, 60, 60, 60, 60, 60, 60, 60, 60} ) (logq = 880) maximum depth: 22, noise budget left: 6 bits
// ---BGV---
// ( 16384, 20, {59, 59, 45, 59, 59, 24, 59, 60} ) (logq = 424) maximum depth: 5, noise budget left: 31 bits
// ---BGV---
// ( 16384, 20, {59, 59, 36, 59, 59, 59, 60} )     (logq = 391) maximum depth: 4, noise budget left: 30 bits
// ---BGV---
// ( 32768, 20, {60, 30, 30, 50, 55, 60, 60, 60, 60, 60, 60} )     (logq = 585) maximum depth: 8, noise budget left: 3 bits
// ---BGV---
// ( 32768, 20, {60, 30, 30, 50, 52, 50, 60, 60, 60, 60, 60} )     (logq = 572) maximum depth: 8, noise budget left: 3 bits
// ---BGV---
// ( 65536, 20, {60, 58, 50, 50, 52, 50, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60} ) (logq = 920) maximum depth: 13, noise budget left: 31 bits
// ---BGV---
// ( 65536, 20, {60, 58, 40, 50, 52, 50, 30, 60, 60, 60, 60, 60, 60, 60, 60, 60} ) (logq = 880) maximum depth: 12, noise budget left: 17 bits