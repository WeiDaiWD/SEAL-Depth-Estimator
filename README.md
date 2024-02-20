# SEAL-Depth-Estimator

Query with a polynomial modulus degree, a bit-size of plaintext modulus, and a vector of bit-sizes of ciphertext moduli to learn the maximum depth (a.k.a. the number of sequential squaring operations on a ciphertext) and the noise budget left when the maximum depth has reached.
This program uses asymmetric encryption and fully split batching (`BatchEncoder`).
Microsoft SEAL by default chooses a centered binomial distribution with deviation close to `3.24` for error and ternary uniform secret keys.

## How to Use

Download, build, and install (Microsoft SEAL)[https://github.com/microsoft/SEAL].

In this directory, run the following scripts.

```
cmake -S . -B build
cmake --build build
./build/bin/seal_depth_estimator
```

To test different parameters, edit the `main` function in (`seal_depth_estimator.cpp`)[seal_depth_estimator.cpp].
