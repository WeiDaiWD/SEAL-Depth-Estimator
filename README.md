# SEAL-Depth-Estimator

Query with a polynomial modulus degree, a bit-size of plaintext modulus, and a vector of bit-sizes of ciphertext moduli to learn the maximum depth (a.k.a. the number of sequential multiplication operations on a ciphertext) and the noise budget left when the maximum depth has reached.
This program uses asymmetric encryption and fully split batching (`BatchEncoder`).

## How to Use

Download, build, and install (Microsoft SEAL)[https://github.com/microsoft/SEAL] by the following script.
```
git clone --recursive https://github.com/microsoft/SEAL.git
cd SEAL
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install  -DSEAL_USE_GAUSSIAN_NOISE=ON
cmake --build build -j
cmake --install build
cd ../
```
Note that Microsoft SEAL by default chooses a centered binomial distribution with deviation close to `3.24` for error and ternary uniform secret keys.
By configuring SEAL_USE_GAUSSIAN_NOISE=ON, SEAL chooses a Gaussian distribution with deviation `3.20` for error and ternary uniform secret keys.


In this repository, run the following scripts.

```
git clone --recursive https://github.com/WeiDaiWD/SEAL-Depth-Estimator.git
cd SEAL-Depth-Estimator
export SEAL_DIR=../SEAL/build/
cmake -S . -B build
cmake --build build
./build/bin/seal_depth_estimator
```

To test different parameters, edit the `main` function in (`seal_depth_estimator.cpp`)[seal_depth_estimator.cpp]. 
