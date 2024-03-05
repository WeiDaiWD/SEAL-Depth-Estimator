# SEAL-Depth-Estimator

Query with a polynomial modulus degree, a bit-size of plaintext modulus, and a vector of bit-sizes of ciphertext moduli to learn the maximum depth (a.k.a. the number of sequential multiplication operations on a ciphertext) and the noise budget left when the maximum depth has reached.
This program uses asymmetric encryption and fully split batching (`BatchEncoder`).

## How to Use

Download, build, and install (Microsoft SEAL)[https://github.com/microsoft/SEAL] by the following script.

```bash
git clone https://github.com/microsoft/SEAL.git
cd SEAL
cmake -S . -B build -DSEAL_USE_GAUSSIAN_NOISE=ON
cmake --build build -j
cd ../
```

Note that Microsoft SEAL by default chooses a centered binomial distribution with deviation close to `3.24` for error and ternary uniform secret keys.
By configuring `SEAL_USE_GAUSSIAN_NOISE=ON`, Microsoft SEAL chooses a discrete Gaussian distribution with deviation `3.20` for error and ternary uniform secret keys.

To run this repository, from the same directory where Microsoft SEAL was cloned, run the following scripts.

```bash
git clone https://github.com/WeiDaiWD/SEAL-Depth-Estimator.git
cd SEAL-Depth-Estimator
cmake -S . -B build -DSEAL_DIR=../SEAL/build/cmake
cmake --build build
./build/bin/seal_depth_estimator
```

To test different parameters, edit the `main` function in (`seal_depth_estimator.cpp`)[seal_depth_estimator.cpp].
