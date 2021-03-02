# darkCON 2021
--------------------------------------

## RE  "Read/Reverse"
&nbsp;

A .pyc python compiled file is given. 
I found a great tool for decompiling it to original code 

https://pypi.org/project/uncompyle6/

The given code is full of no useful names of variables and many lists and encoded strings joking like "This is not the Flag for sure". In the end, I see this piece of code
```python
      def lababa(lebula):
        alalalalalalal = [
                          73, 13, 19, 88, 88, 2, 77, 26, 95, 85, 11, 
                          23, 114, 2, 93, 54, 71, 67, 90, 8, 77, 26, 
                          0, 3, 93, 68
                          ]
        result = ''
        for belu in range(len(alalalalalalal)):
            if lebula[belu] != chr(alalalalalalal[belu] ^ ord(babababa[belu])):
                return 'bbblalaabalaabbblala'
            b2a = ''
            a2b = [122, 86, 75, 75, 92, 90, 77, 24, 24, 24, 25, 106, 
                    76, 91, 84, 80, 77, 25, 77, 81, 92, 25, 92, 87,
                    77, 80, 75, 92, 25, 74, 77, 75, 80, 87, 94, 25,
                    88, 74, 25, 95, 85, 88, 94
                    ]
            for bbb in a2b:
                b2a += chr(bbb ^ 57)
            else:
                return b2a
```

Running the code for b2a, I see some reference of the flag.
I also notice that 'result' is never used, and that block has the var 'babababa' has another reference to a flag. 
So, I do another simple snipet for checking what this operation is having as out put, and I find the flag




```
darkCON{0bfu5c4710ns_v5_4n1m4710ns}
```




&nbsp;

--------------------------------------
## Crypto "Take it easy"
&nbsp;

We are given a zip file. Inside, "givekey.txt" and 2 other password protected files.
Inside it:

```
p = 147310848610710067833452759772211595299756697892124273309283511558003008852730467644332450478086759935097628336530735607168904129699752266056721879451840506481443745340509935333411835837548485362030793140972434873394072578851922470507387225635362369992377666988296887264210876834248525673247346510754984183551
ct = 43472086389850415096247084780348896011812363316852707174406536413629129
e = 3
```
Which seems to be the parameters of a RSA.
p is prime, and 1024 prime length, what corresponds to a 2048 bits RSA key.
e = 3 is vulnerable, as this very good article explains:
https://www.johndcook.com/blog/2019/03/06/rsa-exponent-3/
But the winning card is ct length.
Because it is too small compared to p, the mod operation will have no effect in 
d = e^-1 mod(p-1)(q-1)
So using ct and calculating cubic root we have:
```
pt = 351617240597289153278809
```
Converting to hex, and then encoding to text:
```
Ju5t_@_K3Y
```
Now we decrypt the filez, the cipher.txt contains some bytes values. The other, a python file implementing a simple xor based encryption. 

```python
from struct import pack, unpack
flag = b'darkCON{XXXXXXXXXXXXXXXXXXX}'

def Tup_Int(chunk):
	return unpack("I",chunk)[0]

chunks = [flag[i*4:(i+1)*4] for i in range(len(flag)//4)]
ciphertext = ""

f = open('cipher.txt','w')
for i in range(len(chunks) - 2):
	block = pack("I", Tup_Int(chunks[i]) ^ Tup_Int(chunks[i+2]))
	ciphertext = 'B' + str(i) + ' : ' + str(block) + '\n'
	f.write(ciphertext)
```

We know the first 2 blocks
```
[b"dark", b"CON{"]
```
Reversing the encryption algo, and with the values of cipher.txt, we have a system of 3 XOR equations and 3 incognitas, so solvable
```
darkCON{n0T_Th@t_haRd_r1Ght}
```



