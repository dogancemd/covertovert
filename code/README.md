# Covert Storage Channel that exploits Protocol Field Manipulation using Sequence Number field in TCP

# CENG 435 -  Phase 2 Report

## Group 88

---

### Group Members<br>

---
- Doğancem Duran - 2521508
- Kerem Yılmaz - 2522191

### Github

---
[Project Repository](https://github.com/dogancemd/covertovert)


## About
This is an implementation of covert channel which exploits sequence number field in TCP packets. This allows you to send covert messages between two hosts in a open network.

## Algorithm

This algorithm is built upon the pseudo random number generation techniques. If seed is known a PRNG(pseudo random number generator) will produce the same sequence of numbers in the exact order. The sender and the receiver will agree on a seed to create a common PRNG, and the sender will also have a RNG to randomize the sent packages. They will also agree upon a common odd prime number greater than 3 and ideally smaller or equal to 97. This prime number and common PRNG will be used to determine the bit.

The bit determination will be done by taking the modulus of the numbers with the prime chosen, and checking their equality. If the remainders are equal that gives us a "1" for \[Bit0\]. Otherwise the packet encodes a "0" for \[Bit0\]. Then we check the situation for even or oddness for the number we got. If both are even or both are odd, that encodes a "1" for \[Bit1\]. If their evenness are different then it is a "0" for \[Bit1\]. Then we add \[Bit0\]\[Bit1\] to our cumulative message. And if the first remainder check was "1" then we advance our awaiting number to next.


### Sender
- Methodwise, the sender logic starts with the initial definition of two PRNGs(*pseudo random number generator*), one of which handles equivalent, while the other handles the random selection of the character order in the message to be sent. The main PRNG will produce random numbers between the range of (8\*prime_modulus, 20\*prime_modulus).

- We then use the prime modulus to check the remainder of the expected number from the main PRNG.
- For \[Bit0\]:
    - If we are going to send a "1" bit then we need a number that satisfies the remainder check. For that we can take the original expected number and add a random_int(-5,5)\*prime_modulus. If it is a "0" bit then we make sure it doesn't satisfy.
- For \[Bit1\]:
    - We need to check for the evenness. If we want it to be evenness is not what we want, we can simply add the prime_modulus to change it evenness without changing the remainder.

    
### Receiver

- When receiver is run, a process runs to hold a queue that stores any upcoming packets from the sender. As a packet is put into the queue, the ones at the top are claimed and processed by the receiver.
- Upon the start of bit determination process, main PRNG is used to create randomized values based on the corresponding seed. Then, the affirmation process applies the same steps explained in the Algorithm part to apply the prime modulus and the evenness check on the number got to get 2 bits of the message.
- After a series of packets are determined two bits based on sequence affirmation process until we hit the character "." with the final 8 bits, the final message is then formed from all the approved bits' combination.


### Capacity
When measured the approximate capacity is between 76 and 80 bits per second. This value is measured by creating a random message length of 16, then recording the time of the binary message send loop in send function and dividing 128 by that value. The native system used in this testing can be seen below:

![Screenshot_20241228_100005](https://hackmd.io/_uploads/S1UYz7pryg.png)


## Parameters
#### Sender
- seed:A integer value to initialie a random number generator. Should be the same with seed given to receiver.
- prime_modulus:an integer value which is an odd prime number between 7 and 97. Should be the same as given to receiver.
- dst: Should be the ip address or host name of the receiver host. If not given, default value is "receiver"
#### Receiver
- seed:A integer value to initialie a random number generator. Should be the same with seed given to sender.
- prime_modulus:an integer value which is an odd prime number between 7 and 97. Should be the same as given to sender.
- dst: Should be the ip address or host name of the sender host. If not given, default value is "sender"

