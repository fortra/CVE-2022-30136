# CVE-2022-30136 Windows Network File System Remote exploit PoC

author: [Ricardo Narvaja](https://twitter.com/ricnar456)

For demonstration purposes only. Complete exploit works on vulnerable Windows Server systems.

Checkout the writeup [Analysis of CVE-2022-30136 “Windows Network File System Vulnerability“](https://www.coresecurity.com/core-labs/articles/analysis-cve-2022-30136-windows-network-file-system-vulnerability).

# Usage

## Analysis of CVE-2022-22029 “Windows Network File System vulnerability“

I wanted to write this article to demonstrate the analysis I did while developing the Core Impact exploit “Windows Network File System Remote” that abuses the [CVE-2022-30136](https://nvd.nist.gov/vuln/detail/CVE-2022-30136) vulnerability.

### 1)The Vulnerability

The Windows Network File System Remote Code Execution vulnerability is a size calculation error that occurs when creating the server response in a COMPOUND REQUEST using version 4.1 of NFS.

The server calculates a smaller size than necessary to allocate the pool, and then, when copying the data to generate the response, overflows the buffer.

The function **Nfs4SvrXdrpGetEncodeOperationResultByteCount** in **nfssvr.sys** is called for each operation and returns a size that is smaller than necessary (4 bytes less for each operation).

### 2)The Patch

A patch was made for **Nfs4SvrXdrpGetEncodeOperationResultByteCount**.

This function is called during each OPERATION of a COMPOSE REQUEST so that it returns the bytes needed for each of them based on the OPCODE. It is then added to the header and other parts of the response. Next, it calculates the final size of the entire response to allocate and then copies on it to reply.

In each case, we can see that the value of the size returned for each operation is four bytes smaller in the vulnerable version than the patched version.

### 3)The Diff

I build the POC for Windows server 2019.

Below is the vulnerable version of nfssvr.sys used for this POC, followed by the patched version for Windows server 2019:

![](media/bdd3d4438bca30db9cf0019ddc5ebdc2.png)

The next image shows CASE 26 in the diff:

![](media/d01f80c055ef351d23fbfb5c0d5a37d7.png)

In the example of CASE 26, we can see that the constant added to the calculated value is 0x2c in the vulnerable version, and 0x30 in the patched version.

The same can be seen in each case corresponding to each OPCODE. The vulnerable one always returns a size four bytes smaller than the patched one.

We are not going to show all the cases because the patch is similar for all OPCODES.

### 4)The usage of the Miscalculated Value

The parent of **Nfs4SvrXdrpGetEncodeOperationResultByteCount** is **Nfs4SvrXdrEncodeCompoundResults**. It reads the number of operations sent in the COMPOUND REQUEST.

In this POC the value is 0x34 (52d). When my POC connects to the server to the port 2049 (the default port to NFS), I need to place a conditional breakpoint for a stop.

![](media/1915348814c82dbf5dc08f206c491546.png)

![](media/2e7235126c010f0e31d91f67a94f132a.png)

In this instance, it stops when number_of_operations=0x34.

![](media/25791e56ad99fac36bd9a00a6128012e.png)

The pool with tag ARGS is allocated here.

![](media/b148fd101e6ed3b096513dc0c0d7591f.png)

I will then create a structure named TAG_ARGS_0x10e0 to reverse the fields.

![](media/0309f6b9c854eafec1abf5e34be81ac0.png)

It copies the number_of_operations into r13 and loops into the vulnerable function once per operation, until the counter reaches the value of r13.

![](media/bf2a6e71742a513eb4455153f2e45e7d.png)

It shows that the first package_OPCODE= 0x35, which corresponds to SEQUENCE in the first mandatory operation in a COMPOUND REQUEST. In the image below, the arrow points to this OPCODE in my package.

![](media/bd23a25f544505928fd7a0a3ac0921eb.png)

Here we can see the arguments of the vulnerable function.

![](media/fd00b8ba363ec2f8504aac6f3426908f.png)

![](media/2d9609a779491032aa1af266b3d4c37a.png)

Inside the vulnerable function it reads the OPCODE and goes to the corresponding CASE.

![](media/7428a9cef95066525f1108b8ec35aea7.png)

Three is subtracted from the original OPCODE value (53).

![](media/920b61ad2cc64f394377a2d751c01db6.png)

And jumps to CASE 50, returning 0x28 to the necessary size for this operation.

![](media/ee9f0fee6cf6ba91e712c043761a23f7.png)

![](media/b3ef3dc97c0c986e699b75f328d18f3f.png)

We can see in the diff how the patched version returns 0x2c.

![](media/be1283535eb33f1bbd756051913bd338.png)

This returned value is added to the previous value of other fields in the response in order to calculate the size of the operations. In this case, this value is 0X40c.


![](media/812d4e0a023d0c1199a1ebd10fba917e.png)

Below we can see the values being added:

![](media/04822ba3b46ed06699fc2cf7d88a3106.png)

When it exits the loop, the total size is calculated. In this case, the total size is 0x1310.

![](media/73d7765a05df9666527cf6ca59e93741.png)

We can guess the difference between the vulnerable version and the patched version by calculating the size, using the formula: **number_of_operations * 4**.

**In this case the allocation in the patched version will be 0x34 * 4 = 0x68 bigger than the vulnerable version.**

![](media/f62bccce8397bcc3cdf265426351429b.png)

After that it adds 0x24. This value is calculated in similar way in both vulnerable and patched versions.

![](media/8cbdba431f3c0d4639d23c59111894ad.png)

It then adds the constant 0xf in both cases.

![](media/a39f6f391b0166186b393e9e681e589b.png)

Up to this point, the size in this example has been 0x1340.

![](media/12662f179b63865fce9d2845a90523ad.png)

Next it reaches rpcxdr_OncRpcBufMgrpAllocate.

![](media/65190e3c584436b4540372541c262b2c.png)

It then moves to r15.

![](media/56917757618aa7ddc4b0097bc865af19.png)

![](media/d5bb3df86228ad01558de35a3906d609.png)

It subtracts one and adds four. It then compares with 0x800.

This miscalculated size is only used if it is bigger than 0x800. For this reason, only a COMPOUND REQUEST will trigger the bug.

![](media/e3e70dd5620f060daf49b663449409da.png)

First it allocates a pool with the size = 0x80 and the tag XdBD.

![](media/5116385deba0a573a1d0591a6386739c.png)

Finally, it allocates the pool for the reply here with the size 0x1398, which adds some constant values.

![](media/37a5f7d21b1264aeda47d6161383c306.png)

It then allocates 0x13a0 (including tag XdBP and header).

![](media/98bdba12ca8ee7bf31dd79327878bf5b.png)

From there, it stores the address of the new allocated pool in the field: **tag_XdBD_0x80.p_TAG_XDBP_0x13a0**.

![](media/22ed4a0d95732d7ad58fe5ba32572350.png)

This points to the address of the reply it is always copying to.

![](media/b68f2b7e49d73d6da04b823246e12082.png)

Then it will start to build the reply header.

![](media/d2a70f0a0b42e06ae96a6ab8a3f1eb4b.png)

The following is an example of how it saves the data to the contain of a temporal pointer and adds four to it.

![](media/bb6a41fb3061120698169bce3269e2fb.png)

![](media/52ecc830a5dd72c1a65c9f2070db4fe8.png)

Below we can see how it copies to the contents of the reply address.

![](media/cd8f1a38bcf651536204a9c6c9e4875e.png)

This writes the first dword and it increases the pointer by four.

![](media/6bcaf936614d9314c8274e22f6500b78.png)

Next it writes the second dword and adds four.

![](media/8ec72a21e55d16588b62459d15bac9fa.png)

![](media/412873759a9b87f1219a629e1d00eb74.png)

After exiting the function, the entire header is written.

![](media/985a90a0bf91882101d443777091f671.png)

After that It returns to nfssvr.sys to continue writing the reply.

![](media/1a621ff34d86779f3cbaf023f43cfb06.png)

It will continue decoding and writing in the reply, adding four to the temporal pointer.

![](media/6377b17e713f0648461f6afab76eb0fa.png)

When it completes the header, it reaches this loop to write all operations. It begins with the first OPCODE 0x35.

![](media/f338b2373b50e5f4a4fdfed6efb91e34.png)

![](media/97164bbfcd310a7bbabd8160e91c5bdc.png)

We can see it writes 0x428 from the start of the pool.

![](media/98662864b773d971cffab22e30036e6d.png)

Now it points after the tag.

![](media/20976697ffb7f23c8027447a812dd17e.png)

![](media/9db4700177cd9b1367b01e85a0010130.png)

By putting a breakpoint here, we can see how all the operations were written.

![](media/b8505fe9053d662a756a7c1a362f5cdb.png)

![](media/b3bc2d38b6e5748db730e745089c6693.png)

After exiting the loop all operations are copied.

![](media/7342efe590fd07731f4d2733653d51fb.png)

Let’s check the end of the pool.

![](media/3f907aade5f6925d67f28f61b6eab195.png)

There we can see the write after the limit.

![](media/4697774547272e7ad4b1c5f2aa977199.png)

The allocation is smaller than the data copied, producing a pool overflow.

This produces a BSOD in the target machine. However, the question is, can we achieve a Remote Code execution, or a Write what where?

I tried a number of opcode combinations to get a reply with a controlled data in the overflowed bytes. Unfortunately, I had no luck.

The maximum tag (controlled by me) only can be placed at the start and has a 0x400 maximum size.

![](media/44013bc6010cb8da89025327dd7280fa.png)

All the other opcodes I tried do not reply with controlled data. Consequently, I don’t think it’s possible or, at the very least, is incredibly difficult get a RCE or elevate privileges with this bug. That said, it may still be possible, as I did not try all the combinations among the great number of possibilities that exist.

### 5) The built of the POC.

For the build of the POC I tried with a client named “NFS CLIENT.” It supports NFS 4.1 and I was able to try different opcodes copying files, editing, creating folders etc.

![](media/f5d922c7205888d4fb2a087759740b8b.png)

In this build, I could make a COMPOUND sample package and adjust the size, the client id, the session id etc.

![](media/562f854b36f2ce919dc65b2df6d9bc81.png)

Next, I sent an EXCHANGE_ID to get the client id, using it to send a CREATE_SESSION and finally the big COMPOUND REQUEST.

![](media/b1cab2ec35b3a6f8247ad252edbc78da.png)

At this point we have bug exploited, it leads to a Remote Code Execution allowing a DoS attack.

We hope you find it useful, if you have any doubt can contact us at [Ricardo.narvaja@fortra.com](mailto:Ricardo.narvaja@fortra.com).

Enjoy!
