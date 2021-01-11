# Like

This repository contains a demonstration of the LIKE protocol. The instructions below explain hot to install and compile the project and how to run the demonstration. In the `doc` folder, you can find a full version of the paper describing the protocol.

## Installation

#### Install dependencies

Install following dependencies : openssl, gmp, uuid, gsl.
Example on Ubuntu :
```bash
sudo apt install libssl-dev libgmp-dev libuuid1 uuid-dev libgsl-dev
```

Compile and install [mcl](https://github.com/herumi/mcl).
Example on Ubuntu :
```bash
git clone git://github.com/herumi/mcl
cd mcl/
make
sudo make install
sudo cp -a lib/* /usr/local/lib/ 
sudo ldconfig
```

Check if libraries are correctly installed :
```bash
sudo ldconfig -p | grep libssl
sudo ldconfig -p | grep libgmp
sudo ldconfig -p | grep libuuid
sudo ldconfig -p | grep libmcl
sudo ldconfig -p | grep libgsl
```
All those commands should have non empty output.

#### Install like demo

You need clang to compile.
Download the repository then compile using make. 
```bash
git clone https://github.com/thibj/like.git
cd like/
make
```

## How to use

Compilation create 2 executables in the root directory of the project : `like_demo` which run a demonstration of the client in a single process and `like_mesure` which run measurements. `like_mesure` can take an argument to specify the amount of trials to run (100 by default).
```bash
./like_demo
./like_mesure
./like_mesure 200
```
