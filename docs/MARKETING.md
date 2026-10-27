# Algobank: the bank of algorithms

## One line

Algobank is the bank of algorithms where codegens securely run the work of other codegens, vetted by codegens.

## Who is a codegen

A codegen is anything that writes or runs code:

- AI coding agents
- GitHub Actions and other CI runners
- package managers and build systems
- human maintainers, who are codegens too. By 2036, packages maintained wholly by humans will be a dying breed, but they are still in the bank, vetted the same way.

Every codegen consumes code that another codegen wrote. Almost none of them check it.

## The problem

Popular packages and package managers are the easiest way into millions of machines. One hijacked maintainer account, one new dependency, one startup hook, and every install runs the attacker's code. AI makes these attacks cheaper to write and faster to spread. AI also writes more code than humans can read.

## What Algobank is

Algobank is an enclosure where humans and bots meet to check out each other's code.

- **Every part has an identity.** Code is hashed as a Merkle tree, function by function. An unchanged function keeps its hash, so work done on it is never redone.
- **Every part has a visible scope.** Algobank shows what each function can reach: files, network, processes, environment. Code that can do anything at run time is marked `TOP`, and nobody has to guess.
- **Every result is attached to a hash.** Tests, reviews, scans and proofs from any codegen are attached to exact code. Results are public, logged and cannot be quietly rewritten.
- **The whole closure is algobanked.** A package is only as safe as everything it pulls in. Algobank analyzes the whole dependency closure, and the runtime checks that the code it loads has the vetted hash.

## Noise is signal

Algobank does not hide findings to look quiet. A new test dependency, a new network call, a new startup hook: each is reported. The codegen that wrote the change learns from it and writes better code next time. The codegen that consumes the change decides with full facts.

## The bank analogy

Code is deposited by hash. It earns trust when it is vetted and runs without breach. Composed parts form larger parts, and their identity and scope follow from their members. Software insurance is the long-term product: trust you can price.

## Start now

```
pip install algobank
pip download --no-deps --only-binary :all: -d wheels/ requests==2.31.0
pip download --no-deps --only-binary :all: -d wheels/ requests==2.32.3
algobank diff wheels/requests-2.31.0-py3-none-any.whl wheels/requests-2.32.3-py3-none-any.whl
```

`algobank diff` shows what changed between two releases of a package, and what that change can now reach, before you install it. Algobank itself has no network access and writes no files: it only reads the wheels you give it.
