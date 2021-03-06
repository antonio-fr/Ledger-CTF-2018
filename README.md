# Ledger Capture The Flag 2018

[Ledger](https://www.ledger.fr/ctf2018/) organized a security & cryptography-related security challenge, from March 20<sup>th</sup> 2018. Capture The Flag (CTF) qualification is made of 3 different tests.

Now the challenge is over, I share, with Ledger permission, how I have found the solutions along with the Python code I used.


## CTF Challenge 1 : The mathematics behind RSA

The challenge is purely **theoretical**. This is a deep dive in **modular arithmetic**, which is heavily used in RSA cryptography. In the RSA crypto-system, the encryption function is <img src="https://latex.codecogs.com/svg.latex?E(x)=x^e\bmod{n}" /> . The challenge is to list all *e* which the number of *x* such as <img src="https://latex.codecogs.com/svg.latex?x=x^e\equivx\pmod{n}" /> is at minimum. Then compute the product of all these values of *e* (modulo 1337694213377816) .

The numbers given are :  
p = nextprime(1337) and q = nextprime(6982)  
So we have : p = 1361 and q = 6983  
n = p * q = 9503863  
<img src="https://latex.codecogs.com/svg.latex?\varphi(n)=n\prod_{p\mid%20n}\left(1-{\frac{1}{p}}\right)" />  
<img src="https://latex.codecogs.com/svg.latex?\varphi(n)=(p-1)*(q-1)=9495520" />


In one given example, p=13, q=37, e = 73, it turns that all the messages *x* are such that <img src="https://latex.codecogs.com/svg.latex?E(x)=x" />. There is no encryption actually with this value, because it outputs the original value for any message.

As a warm-up, we can see if there exists and to find *e* where for **any** <img src="https://latex.codecogs.com/svg.latex?x\in\mathbb{Z}_n" />, we got *E(x)=x* ? We are seeking for *e* such that :
<img src="https://latex.codecogs.com/svg.latex?\forall%20x\in\mathbb{Z}_n,x^e\bmod%20n=x\iff%20e=1\bmod{\lambda(n)}" /> (using a corollary of Euler theorem and multiplicative order)

<img src="https://latex.codecogs.com/svg.latex?\forall%20x\in\mathbb{Z}_n,x^e\bmod%20n=x\iff%20e=k.\lambda(n)+1,k\in\mathbb{N}" />

<img src="https://latex.codecogs.com/svg.latex?\lambda(n)=\operatorname{lcm}{\big(}\lambda(p_{1}^{r_{1}}),\,\lambda(p_{2}^{r_{2}}),\,\ldots,\,\lambda(p_{k}^{r_{k}}){\big)}" />  
<img src="https://latex.codecogs.com/svg.latex?\lambda(n)=lcm(p-1,q-1)" />  
is the Carmichael function.

The *e* number is always less than <img src="https://latex.codecogs.com/svg.latex?\varphi(n)" /> and prime with it. With n = 1361*6983 = 9503863, there is one unique *e* value that matches : e = 4747761.
So taking <img src="https://latex.codecogs.com/svg.latex?\lambda(n)+1" />, you get *E(x)=x* for any message. So there's a chance we can pick up an unfortunate number which make null-encryption when using it? Well, this is a common mistake in the Ledger RSA introduction. There's this kind of error even in [the original RSA paper](https://people.csail.mit.edu/rivest/Rsapaper.pdf), <img src="https://latex.codecogs.com/svg.latex?gcd(e,\varphi)" /> is not enough. *e* needs to be less than <img src="https://latex.codecogs.com/svg.latex?\lambda(n)=lcm(p-1,q-1)" /> , instead of <img src="https://latex.codecogs.com/svg.latex?\varphi(n)=(p-1)*(q-1)"/>. So this avoids having *e* nulling the encryption. In practice, *e* is virtually always the largest known Fermat prime <img src="https://latex.codecogs.com/svg.latex?2^{2^4}+1=65537" />. This value is a recommended value in many standards (e.g. [DKIM RFC4871](https://www.ietf.org/rfc/rfc4871.txt): "*SHOULD use a public exponent of 65537*"). The primality of *e* makes <img src="https://latex.codecogs.com/svg.latex?\gcd(p-1,e)=1\implies%20p\not\equiv%201\pmod%20e" /> and its form makes computation (encryption) very fast. Using a fixed *e*, the key generation is just finding 2 primes *p* and *q*, then computing the modular inverse <img src="https://latex.codecogs.com/svg.latex?d=e^{-1}\bmod\lambda(n)" />. In the RSA system, the public numbers are *(n,e)*, and the secrets are *(d, p, q)*. Note that *&lambda;(n)* and *&phi;(n)* are secrets, as they need *p* and *q* for their computation, to actually compute them from *n* requires to factor *n*. The point is that *p* and *q* can be computed easily from *&lambda;(n)* and *&phi;(n)*. 

Yet, the challenge is the opposite, we need to get all values of *e* where there is a minimal number of messages where *E(x)=x*.
We are now seeking for the number of solutions of :

<img src="https://latex.codecogs.com/svg.latex?E(x):x^e\equiv%20x\pmod{n}" />

Let's begin with p prime :
<img src="https://latex.codecogs.com/svg.latex?E(x):x^e\equiv%20x\pmod{p}" />
<img src="https://latex.codecogs.com/svg.latex?x^e\equiv%20x\pmod{p}\iff%20x^e-x\equiv0\pmod{p}\iff%20x(x^{e-1}-1)\equiv0\pmod{p}" />  
<img src="https://latex.codecogs.com/svg.latex?\iff%20x^{e-1}\equiv1\vee%20x\equiv0\pmod{p}" /> (whether p is factor of x)

We need to find out the number of modular *e-1<sup> th</sup>* roots of unity.  
The number of solutions *(x)* is :  
<img src="https://latex.codecogs.com/svg.latex?|\%20x:x^{e-1}\equiv1\pmod{p}\%20|=\langle%20e-1\rangle\subset\mathbb{Z}_p" />  
<img src="https://latex.codecogs.com/svg.latex?=gcd(e-1,\varphi(p))=gcd(e-1,p-1)" />

Adding 1 solution for the "x=0", then computing the exact same for *q*, using the Chinese remainder theorem, we finally get :  
<img src="https://latex.codecogs.com/svg.latex?|\%20x:x^{e}\equiv%20x\pmod{n}\%20|=(1+gcd(e-1,p-1))\times(1+gcd(e-1,q-1))" />

As *p-1* or *q-1* are even, the minimum expected is 2 for each *gcd*. Minimal values (=2) are expected when *e* is odd. To get the maximum speed, testing *gcd(e-1,p<sub>i</sub>-1)==2* is thus sufficient.


I wrote a Python software that filters out all the odd <img src="https://latex.codecogs.com/svg.latex?e\in%202\le%20e%3C\varphi(n)" /> which complies :
<img src="https://latex.codecogs.com/svg.latex?e:\begin{cases}gcd(e-1,p-1)=2\land%20gcd(e-1,q-1)=2\\gcd(e,\varphi(n))=1\end{cases}" />


A second optimization would be to use the empirical fact that :
<img src="https://latex.codecogs.com/svg.latex?gcd(e-1,p-1)=2\land%20gcd(e-1,q-1)=2%20\implies%20gcd(e,\varphi(n))=1" />

So this is not necessary to check <img src="https://latex.codecogs.com/svg.latex?gcd(e,\varphi(n))=1" /> after <img src="https://latex.codecogs.com/svg.latex?gcd(e-1,p-1)=2\land%20gcd(e-1,q-1)=2" />. As this is not obvious to theoretically proof this, I let this check in the code.  
The actual python code CTF1 takes about 8 seconds on a standard PC.


The final result is <img src="https://latex.codecogs.com/svg.latex?\prod%20e_i\mod{1337694213377816}=501635330016681" />


This challenge shows that to just getting the number of roots of a composite number, depends on its factors. Here, this is <img src="https://latex.codecogs.com/svg.latex?\prod(1+gcd(X,p_i-1))" />, requiring the factors *p<sub>i</sub>* of *n*.

A more detailed proof of the formula is given in §3 (Theorem 3) in :  
G.R. Blakley, I. Borosh  
*RSA public key cryptosystems do not always conceal messages*  
Computers & Mathematics with Applications, Issue 5 (1979), p.169-178 [LINK](https://www.sciencedirect.com/science/article/pii/0898122179900397)


## CTF 2 : Access control

The CTF2 is about running a full statically linked binary, doing a full decompilation to reverse engineering and extract the private key. Alternatively, runs in a VM, injecting faults and reading memory. It is also the harder of the 3 challenges. To compare, only half of the people who solve CTF#1, solved this challenge.  
I tried the padding oracle technique up to 2 chars on it. Many timing measurements, nothing was conclusive. As I'm not familiar with this kind of analysis, I gave up on this challenge.


## CTF 3 : \$camcoin is the new Bitcoin

By far, my favorite, I solved it in hours. On top of the cryptographic part, I enjoy the story of people building a new crypto-currency, supposedly better than Bitcoin, and turns out there are some flaws where you can compute very fast the private keys of the transactions. This is not fully fictional as [some real stories are very similar](http://blog.lekkertech.net/blog/2018/03/07/iota-signatures/). And I wouldn't talk this time about bugs in Solidity smart contracts.

When using the Digital Signature (DSA) standard (NIST FIPS PUB 186), there is an ephemeral secret key during the signature, and it needs to be secret. If an attacker knows this number *k* or can guess it from a bad random source, he can compute your private key.  
To begin, I started to seek for *k* corresponding to a fixed minute time in February/March 2018. This doesn't give anything conclusive.

Also if an attacker can draw a relation between 2 *k* used, the most obvious and simple is equality, he can compute your private key (*d*). From 2 signatures, with an identical *k*, <img src="https://latex.codecogs.com/svg.latex?H(m_1)\mapsto(r_1,s_1),H(m_2)\mapsto(r_2,s_2)" /> :  
<img src="https://latex.codecogs.com/svg.latex?k={\frac{H(m_2)-H(m_1)}{s_2-s_1}},s_1=\frac{H(m_1)+r_1.d}{k}\rightarrow\displaystyle%20d={\frac{s_1.k-H(m_1)}{r}}" />

That's what happened with the Sony PS3 for example. Sony engineers used the same *k* every time to sign code. In 2010, some [hackers extracted a private key](https://youtu.be/Eag0VyRTld8?t=500) from the PS3 platform. The [RFC6979 standard](https://tools.ietf.org/html/rfc6979) was designed some years ago to overcome these issues. It recommends to sign with a deterministic *k* computed from the private key and the message. This standard is mostly used today, as there is no more need to have a random source to sign and this protects from *k* reuse.

Finally, I sought for identical *k*. This was the right path, as 2 signatures have identical *k*.
A signature is *(r,s)* and <img src="https://latex.codecogs.com/svg.latex?r=(k.G)_x" /> . So 2 identical *k* lead to 2 identical *r*. The 2 signatures which have the same *k*, have an identical starting in base64. Having the 2 signatures with the same *r*, I computed *k*, then *d<sub>Bob</sub>*.

I used [my old 4 years old bitcoin and ECDSA library](https://github.com/antonio-fr/Fast_Sign_Verify), with some added code to get key recovery. The CTF3 file provided does all the work (takes ~0.5s on a standard PC) :
 - read the text file provided by Ledger
 - check that the example they provide is correct (test my software)
 - seek for 2 signatures with the same *k/r*
 - extract *k* and then *d<sub>Bob</sub>*
 - sign the given message

The extraction gives k = 1486220568. That means, according to the system description, that Bob signed his transaction on Saturday February 4th 2017 at 15h02:48 GMT. Probably, he signed 2 transactions in the same second, making 2 transactions with same *k*. That's the flaw in the "\$camcoin" system imagined by Ledger team. DSA shall always use a random *k* or a RFC6979 deterministic one. For example, using this "\$camcoin", if one broadcasts the transaction just after signing (a standard crypto-currency use), it is really easy to find out the value of *k* used and then get the private key.

Here from *k* used twice, we get the Bob's secret key :  
<img src="https://latex.codecogs.com/svg.latex?d_{Bob}\%20_{(b10)}=\textnormal{36221617151509169543226411876758718954222210470729632659581052280059046489003}" />  
<img src="https://latex.codecogs.com/svg.latex?d_{Bob}\%20_{(b16)}=\textnormal{5014b573432161171a4c8312f67abe5cfe79d83382c1fea1dfb2c9c268216bab}" />


Then signing the following message (*m*) with *d<sub>Bob</sub>* and *k* = 1521543600
```
Amount:1000000 From:1Kx74VzYPdnJ9xxYQRAap4oNsqaAdUdNCA To:14pHuKrkRhLKsW6zxHKQ64DFGyKQffj7GW
```
  
<img src="https://latex.codecogs.com/svg.latex?H(m)=\rm{SHA256}(\rm{SHA256}(m))" />  
<img src="https://latex.codecogs.com/svg.latex?H(m)_{(b10)}=\textnormal{99418066424312055700057700639792607513261906432102262516632065974921000930487}" />  
<img src="https://latex.codecogs.com/svg.latex?H(m)_{(b16)}=\textnormal{dbcca1aab480b507200cf72414b6f01c6dda6ed701bcf6b75f53502881b84cb7}" />


The final signature (with "canonical" *s, s<n/2* ) in base64 is :
```
HKaLZ/jSgiehh7cyhP5A7AXfEEwuQudjJiJqQLn2qa6RSzWQeeCrbVIdw0vMpnYHqfUN9CQDI2LKlmHx84jTfjs=
```



## Conclusion

The Ledger challenge was covering many areas in computer science security and cryptography. I really enjoyed working on it. I loved this mix of theory, practice and imagination. It was all about finding what could be the issue in the system to break in, making some theories in order to build a small program to give a solution in seconds.

Ledger did a quick answers explanation afterwards [here](https://www.ledger.fr/2018/06/01/ctf-complete-hw-bounty-still-ongoing-2-337-btc/), and uploaded some software of the contestants on [Github](https://github.com/LedgerHQ/CTF/tree/master/ctf2018)

The first challenge, is fully theoretical, so I imagine there are many ways to reach the solution. I hope I didn't write so much errors in the theory, I don't feel at home in parts like that.  
Sadly, I couldn't make the hardest one, CTF#2. Still, with this one I learned the most because I didn't know many things about it and I did make a lot of researches. I'll also learn even more with the answers detailed of this challenge, from others and from Ledger.  
CTF#3 was really my cup of tea, I could even reused some of my old codes about ECDSA and Bitcoin signatures to help the computation.  

This challenge was helpful to identify some French guys who are building hardware infosec labs to break hardware security devices, such as what Ledger is developing. I'm greeting [NinjaLab](https://ninjalab.io/team/), [TiempoSecure](http://www.tiempo-secure.com/company/about-tiempo-secure/), and [CryptoExperts](https://www.cryptoexperts.com/people/).

Thanks for making this challenge Ledger, this is cool because it costs money (time spent) and no direct revenue, but this is really useful. That's also why I took time to solve it within the normal course of learning and technological intelligence for my infosec and blockchain firm [BitLogiK](https://bitlogik.fr/). Infosec and data security is a science involving many domains, and also it is constantly evolving. It moves also very fast thanks to the digital world and global communication are growing very quickly. Obviously, crypto-currencies are a match between money and infosec : wealth is directly protected by cryptography and data access control.

The ranking of the challenges is available [here](https://docs.google.com/spreadsheets/d/1ZuSOwIkqvzr5jAVj66Hs3iekIeKTHRSpujhtpcy4PCI/edit#gid=0).

Feel free to open an issue in this repository if you have any comments or questions about this challenge report.


Thanks to Ledger and all participants!

