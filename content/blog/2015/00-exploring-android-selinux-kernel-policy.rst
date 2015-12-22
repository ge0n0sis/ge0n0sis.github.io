Exploring Android's SELinux Kernel Policy
#########################################

:date: 2015-12-22
:tags: android, selinux, seandroid, sedump
:category: seandroid
:authors: Fernand LONE SANG
:summary: 
    SELinux is part of the Android security model since Android 4.3. This article
    covers various aspects of the SELinux kernel policy in Android. I
    have dissected how the monolithic policy file is created in current
    Android's version. While analyzing ``checkpolicy`` source code, I digress
    a little on the policy file format. Finally, I present a tool to
    decompile a ``sepolicy`` file into a semantically equivalent
    set of SELinux statements (and which can be compiled back into a ``sepolicy``!).


.. role:: bash(code)
   :language: bash

.. role:: cpp(code)
   :language: cpp

Introduction
------------

Since Android 4.3, SELinux is part of the Security Enhancements for Android and
contributes to the Android security model by enforcing mandatory access control
over all processes and by confining privileged processes besides Linux's native
discretionary access control.

This article focuses on Android's SELinux kernel policy. I explain in detail
how SELinux statements are transformed into a binary file. I dissect briefly
its file format and, I introduce a proof-of-concept tool I wrote, `sedump
<https://github.com/ge0n0sis/sedump/>`_, to get back SELinux equivalent
statements from a binary file extracted from an Android ROM for instance.

Building Android sepolicy
-------------------------

The journey begins with understanding how Android's SELinux kernel policy
is generated. Source files required to build Android's `sepolicy` can be
downloaded either from the `Android Source Tree` (`external/sepolicy
<https://android.googlesource.com/platform/external/sepolicy>`_) or from the
`Security Enhancements (SE) for Android` repositories (`external-sepolicy
<https://bitbucket.org/seandroid/external-sepolicy/>`_).

.. code-block:: bash

    $ git clone https://android.googlesource.com/platform/external/sepolicy
    $ cd sepolicy
    $ ls
    access_vectors          bluetoothdomain.te  dnsmasq.te            [...]
    adbd.te                 bluetooth.te        domain_deprecated.te  [...]
    Android.mk              bootanim.te         domain.te             [...]
    [...]
    
Like any other Android project, rules to build output files are described
inside a make file named ``Android.mk``. Let us dissect that file, especially
rules to build the :bash:`sepolicy` target:

.. code-block:: bash

    POLICYVERS ?= 29
    [...]
    LOCAL_MODULE := sepolicy
    LOCAL_MODULE_CLASS := ETC
    LOCAL_MODULE_TAGS := optional
    LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

    include $(BUILD_SYSTEM)/base_rules.mk
    sepolicy_policy.conf := $(intermediates)/policy.conf
    [...]
    $(LOCAL_BUILT_MODULE): $(sepolicy_policy.conf) $(HOST_OUT_EXECUTABLES)/checkpolicy
        @mkdir -p $(dir $@)
        $(hide) $(HOST_OUT_EXECUTABLES)/checkpolicy -M -c $(POLICYVERS) -o $@ $<
        $(hide) $(HOST_OUT_EXECUTABLES)/checkpolicy -M -c $(POLICYVERS) -o \
            $(dir $<)/$(notdir $@).dontaudit $<.dontaudit

When run, the :bash:`sepolicy` target outputs two files, ``sepolicy`` and
``sepolicy.dontaudit``, into the :bash:`$(intermediates)` folder defined by the
Android build system. These two files are generated with ``checkpolicy`` by
providing respectively :bash:`$(sepolicy_policy.conf)` and
:bash:`$(sepolicy_policy.conf).dontaudit` as input.

.. code-block:: bash

    MLS_SENS=1
    MLS_CATS=1024
    [...]
    sepolicy_policy.conf := $(intermediates)/policy.conf
    $(sepolicy_policy.conf): PRIVATE_MLS_SENS := $(MLS_SENS)
    $(sepolicy_policy.conf): PRIVATE_MLS_CATS := $(MLS_CATS)
    $(sepolicy_policy.conf): PRIVATE_ADDITIONAL_M4DEFS := $(LOCAL_ADDITIONAL_M4DEFS)
    $(sepolicy_policy.conf): $(call build_policy, $(sepolicy_build_files))
        @mkdir -p $(dir $@)
        $(hide) m4 $(PRIVATE_ADDITIONAL_M4DEFS) \
            -D mls_num_sens=$(PRIVATE_MLS_SENS) -D mls_num_cats=$(PRIVATE_MLS_CATS) \
            -D target_build_variant=$(TARGET_BUILD_VARIANT) \
            -s $^ > $@
        $(hide) sed '/dontaudit/d' $@ > $@.dontaudit

The :bash:`sepolicy_policy.conf` target outputs two files,
:bash:`$(intermediates)/policy.conf` and :bash:`$(intermediates)/policy.conf.dontaudit`.
The general-purpose macro processor M4 expands files listed in the
:bash:`$(sepolicy_build_files)` variable in order to generate ``policy.conf`` and
its stripped off version ``policy.conf.dontaudit``.
:bash:`$(sepolicy_build_files)` simply lists all source files required to build the
Android SELinux kernel policy:

.. code-block:: bash

    sepolicy_build_files := security_classes initial_sids access_vectors \
        global_macros neverallow_macros mls_macros mls policy_capabilities \
        te_macros attributes ioctl_macros *.te roles users initial_sid_contexts \
        fs_use genfs_contexts port_contexts

Let us precise that this file list can be overriden with board specific files
while executing :bash:`$(call build_policy, $(sepolicy_build_files))`. This is
an expected behaviour in Android build system when defining :bash:`BOARD_SEPOLICY_*`
variables.

All the brick put back together, one can generate easily a ``sepolicy`` file outside
of Android build system. ``checkpolicy`` is not an android-specific tool, thus
one provided with the `setools <https://github.com/TresysTechnology/setools3>`_
package in your default Linux distribution should be enough:

.. code-block:: bash

    $ sudo apt-get install m4 setools
    $ m4 -D mls_num_sens=1 -D mls_num_cats=1024 -D target_build_variant=user \
         -s security_classes initial_sids access_vectors global_macros \
            neverallow_macros mls_macros mls policy_capabilities te_macros \
            attributes ioctl_macros *.te roles users initial_sid_contexts \
            fs_use genfs_contexts port_contexts > policy.conf
    $ checkpolicy -h
    usage:  checkpolicy [-b] [-d] [-U handle_unknown (allow,deny,reject)] \
                        [-M][-c policyvers (15-29)] [-o output_file]      \
                        [-t target_platform (selinux,xen)] [input_file]
    $ checkpolicy -M -c 29 -o sepolicy policy.conf
    checkpolicy:  loading policy configuration from policy.conf
    checkpolicy:  policy configuration loaded
    checkpolicy:  writing binary representation (version 29) to sepolicy
    $ file sepolicy
    sepolicy: SE Linux policy v29 MLS 8 symbols 7 ocons

``checkpolicy`` accepts numerous options. The :bash:`-M` option is a flag to
indicate that the compiled policy should embed multi-level security
statements and the :bash:`-c` specifies the policy version.

Understanding the SELinux Kernel Policy File Format
---------------------------------------------------

Let us dig the subject deeper by understanding how the SELinux textual
statements are transformed into a binary kernel policy. Unfortunately for us,
the SELinux kernel policy file format is not documented, probably because it is
a complex format which depends heavily on the policy version.

The main entry point for `checkpolicy
<http://androidxref.com/6.0.0_r1/xref/external/selinux/checkpolicy/>`_ is
located in `checkpolicy.c
<http://androidxref.com/6.0.0_r1/xref/external/selinux/checkpolicy/checkpolicy.c>`_.
In a few words, a SELinux policy is represented in memory by a :cpp:`policydb_t` data
structure. It is zeroed and initialized by the `policydb_init()
<http://androidxref.com/6.0.0_r1/xref/external/selinux/checkpolicy/checkpolicy.c#571>`_
method, and its members are set while parsing SELinux statements using LEX and
YACC (`policy_scan.l
<http://androidxref.com/6.0.0_r1/xref/external/selinux/checkpolicy/policy_scan.l>`_
and `policy_parse.y
<http://androidxref.com/6.0.0_r1/xref/external/selinux/checkpolicy/policy_parse.y>`_)
in `read_source_policy()
<http://androidxref.com/6.0.0_r1/xref/external/selinux/checkpolicy/checkpolicy.c#583>`_.
Once fully parsed, ``checkpolicy`` outputs the resulting SELinux kernel policy
binary to the path specified in the command line. The method `policydb_write()
<http://androidxref.com/6.0.0_r1/xref/external/selinux/checkpolicy/checkpolicy.c#632>`_
is in charge of writing a :cpp:`policydb_t` on the disk.

I deliberately skip the parsing of the SELinux statement and I assume that the
policy has been loaded and the :cpp:`policydb_t` data structure is ready to be
written on the disk. The following listing handles writing the binary policy on
the disk:

.. code-block:: c

    struct policy_file pf;
    [...]
    if (outfile) {
        outfp = fopen(outfile, "w");
        [...]
        if (!cil) {
            printf("%s:  writing binary representation (version %d) to %s\n",
                   argv[0], policyvers, outfile);
            policydb.policy_type = POLICY_KERN;
    
            policy_file_init(&pf);
            pf.type = PF_USE_STDIO;
            pf.fp = outfp;
            ret = policydb_write(&policydb, &pf);
            [...]
        } else {
            [...]
        }
        fclose(outfp);
    }

:cpp:`policydb_write()` expects two arguments: a reference to a
:cpp:`policydb_t` data structure and a reference to a :cpp:`struct
policy_file`. The later is an abstration layer for possible input or output
formats (memory-mapped memory or basic I/O). The :cpp:`struct policy_file` is
defined as follows in `libsepol
<http://androidxref.com/6.0.0_r1/xref/external/selinux/libsepol/include/sepol/policydb/policydb.h#664>`_:

.. code-block:: c

    /* A policy "file" may be a memory region referenced by a (data, len) pair
       or a file referenced by a FILE pointer. */
    typedef struct policy_file {
    #define PF_USE_MEMORY  0
    #define PF_USE_STDIO   1
    #define PF_LEN         2 /* total up length in len field */
        unsigned type;
        char *data;
        size_t len;
        size_t size;
        FILE *fp;
        struct sepol_handle *handle;
    } policy_file_t;

Let us focus now on :cpp:`policydb_write()` (defined in `libsepol/src/write.c
<http://androidxref.com/6.0.0_r0/xref/external/selinux/libsepol/src/write.c#1942>`_)
to understand the format of the binary policy. SELinux policies can be
defined via a SELinux kernel policy or a SELinux module policy: as we are
only interested in SELinux kernel policies, one can focus only on code
path satisfying :cpp:`p->policy_type == POLICY_KERN` in the source code.

:cpp:`policydb_write()` begins an SELinux kernel policy binary with a *magic*
number that holds the type of policy. It writes then information related to
policy compatibility: the *length* of a standardized string identifier and the
*string identifier* itself ("SE Linux" or "XenFlask" or "SELinux Module"), the
*policy version* number, the *configuration* (e.g, MLS policy or not), the
*symbol array* and *object context array* sizes. To illustrate the file format,
I wrote an incomplete 010Editor template that parses the SELinux kernel policy
header. 

.. code-block:: c

    $ cat SELinux.bt
    typedef enum <uint> {
        MLS    = 1
    } CONFIG;

    typedef struct {
        uint magic <format=hex>; // 0xf97cff8c (SELINUX_MAGIC) or 0xf97cff8d (SELINUX_MOD_MAGIC)
        uint target_len;
        if (target_len > 0)
            uchar target[target_len]; // "SE Linux" or "XenFlask" or "SELinux Module"
        uint version;
        CONFIG config;
        uint sym_num;
        uint ocon_num;
    } SELinuxPolicyHeader;
    
    typedef struct {
        SELinuxPolicyHeader header;
    } SELinuxPolicy;
    
    LittleEndian();
    while(!FEof())
    {
        SELinuxPolicy policy;
        Warning("Incomplete template, stopped." );
        return -1;
    }

Using `Python format parser (pfp) <https://github.com/d0c-s4vage/pfp>`_, one
can dissect an ``sepolicy`` header with the above mentionned template. As
expected, we manage to retrieve the same piece of information as ``file``:

.. code-block:: bash

    $ cat pfp-parse.py
    import sys, pfp

    dom = pfp.parse(data_file=sys.argv[1], template_file=sys.argv[2])
    print(dom._pfp__show(include_offset=True))
    $ python fpf-parse.py sepolicy SELinuxPolicy.bt
    0000 struct {
        0000 policy     = 0000 struct {
            0000 header     = 0000 struct {
                0000 magic      = UInt(4185718668 [f97cff8c])
                0004 target_len = UInt(8 [00000008])
                0008 target     = UChar[8] ('SE Linux')
                0010 version    = UInt(29 [0000001d])
                0014 config     = Enum<UInt>(1 [00000001])(MLS)
                0018 sym_num    = UInt(8 [00000008])
                001c ocon_num   = UInt(7 [00000007])
            }
        }
    }
    $ file sepolicy
    sepolicy: SE Linux policy v29 MLS 8 symbols 7 ocons

The SELinux kernel policy header is followed by two serialized :cpp:`ebitmap_t`
(`libsepol/ebitmap.c
<http://androidxref.com/6.0.0_r1/xref/external/selinux/libsepol/src/ebitmap.c>`_):
on that stores :code:`polcap` statements and another one for :code:`permissive`
statements. To output these bitmaps, the template has been updated with the
following:

.. code-block:: bash
    
    $ cat SELinuxPolicy.bt
    [...]
    } SELinuxPolicyHeader;
    
    typedef struct {
        uint   start;
        uint64 bits;
    } BITMAP;
    
    typedef struct {
        uint size;
        uint highbit;
        uint count;
        BITMAP node[count];
    } SELinuxPolicyEBitmap;
    
    typedef struct {
        SELinuxPolicyHeader  header;
        if (header.version >= 22)
            SELinuxPolicyEBitmap polcap;
        if (header.version >= 23)
            SELinuxPolicyEBitmap permissive;
    } SELinuxPolicy;
    [...]
    $ python fpf-parse.py sepolicy SELinuxPolicy.bt
    0000 struct {
        0000 policy     = 0000 struct {
            [...]
            0020 polcap     = 0020 struct {
                0020 size       = UInt(64 [00000040])
                0024 highbit    = UInt(64 [00000040])
                0028 count      = UInt(1 [00000001])
                002c node       = BITMAP[1]
                    002c node[0] = 002c struct {
                            002c start      = UInt(0 [00000000])
                            0030 bits       = UInt64(3 [0000000000000003])
                        }
            }
            0038 permissive = 0038 struct {
                0038 size       = UInt(64 [00000040])
                003c highbit    = UInt(0 [00000000])
                0040 count      = UInt(0 [00000000])
                0044 node       = BITMAP[0]
            }
        }
    }

In AOSP, `policycap` statements are defined in `policy_capabilities
<https://android.googlesource.com/platform/external/sepolicy/+/master/policy_capabilities>`_.
There are two policy capability defined, :code:`network_peer_controls` and
:code:`open_perms`, which is consistent with the above displayed bitmap and the
meaning of each bit defined in `libsepol/polcaps.c
<http://androidxref.com/6.0.0_r1/xref/external/selinux/libsepol/src/polcaps.c#16>`_.
Furthermore, no permissive type is defined in the AOSP SELinux configuration
which likely explain the empty bitmap for ``permissive``.

Unfortunately, the remaining SELinux kernel policy is a bit tedious to explain
as there are many data structures involved and to serialize:
:cpp:`policydb_write()` outputs identifiers declarations (common, types,
attributes, etc.) and the defined access vector rules (allow, deny, dontaudit,
etc. rules.). Let us detail the serialization of common permission sets.

Common permission sets are stored in the :cpp:`policydb_t` data structure in
the :cpp:`symtable[0].table` field. It is a hash table with the common
permission set identifier as key and a reference to a :cpp:`common_datum_t` as
value. The latter is a structure with a :cpp:`datum_t` (i.e., index) and an
hash table listing the permission associated with the common identifier. All
these structures are defined in `libsepol/sepol/policydb/policydb.h
<http://androidxref.com/6.0.0_r1/xref/external/selinux/libsepol/include/sepol/policydb/policydb.h#106>`_.

In ``libsepol``, :cpp:`hashtab_t` hash tables are all serialized in the same
way. The serialized structure contains a :cpp:`nprim` member, keys and values
of the hash table and additionnally :cpp:`nelem`, representing the number of
elements stored in the hash table. These members can be found in the serialized
:cpp:`symtable[0].table` and :cpp:`common_datum_t`. As for strings identifiers,
they are simply serialized with the string itself and its length. Here is an
updated template to parse the common permission group:

.. code-block:: bash

    $ cat SELinuxPolicy.bt
    [...]
    } SELinuxPolicyEBitmap;

    typedef struct {
        uint len;
        uint datum;
        uchar identifier[len];
    } PERMISSION;
    
    typedef struct {
        uint len;
        uint datum;
        uint perm_nprim;
        uint perm_nelem;
        uchar identifier[len];
        PERMISSION permission[perm_nelem];
    } COMMON;
    
    typedef struct {
        uint nprim;
        uint nelem;
        switch (i) {
            case 0: // common statements
                COMMON common[nelem];
            default: // not handled yet
                return -1;
        }
    } SYMBOL;
    
    typedef struct {
        SELinuxPolicyHeader  header;
        if (header.version >= 22)
            SELinuxPolicyEBitmap polcap;
        if (header.version >= 23)
            SELinuxPolicyEBitmap permissive;
        for (local int i = 0; i < header.sym_num; i++) {
            SYMBOL symbol;
        }
    } SELinuxPolicy;
    [...]
    $ python fpf-parse.py sepolicy SELinuxPolicy.bt
    0000 struct {
        0000 policy     = 0000 struct {
            [...]
            0044 symbol     = 0044 struct {
                0044 nprim      = UInt(3 [00000003])
                0048 nelem      = UInt(3 [00000003])
                004c common     = COMMON[3]
                    004c common[0] = 004c struct {
                            004c len        = UInt(6 [00000006])
                            0050 datum      = UInt(2 [00000002])
                            0054 perm_nprim = UInt(22 [00000016])
                            0058 perm_nelem = UInt(22 [00000016])
                            005c identifier = UChar[6] ('socket')
                            0062 permission = PERMISSION[22]
                                0062 permission[0] = 0062 struct {
                                        0062 len        = UInt(6 [00000006])
                                        0066 datum      = UInt(10 [0000000a])
                                        006a identifier = UChar[6] ('append')
                                    }
                                0070 permission[1] = 0070 struct {
                                        0070 len        = UInt(4 [00000004])
                                        0074 datum      = UInt(11 [0000000b])
                                        0078 identifier = UChar[4] ('bind')
                                    }
                                007c permission[2] = 007c struct {
                                        007c len        = UInt(7 [00000007])
                                        0080 datum      = UInt(12 [0000000c])
                                        0084 identifier = UChar[7] ('connect')
                                    }
            [...]

As the process is slightly the same for the other statements, I will leave to
the curious reader the decoding of the remaining binary as an exercise.


Dumping sepolicy back to policy.conf
------------------------------------

So far, I assumed that one had the source code to build the ``sepolicy`` file.
Unfortunately, real life is far from being that easy and all you have, when
analyzing an Android system, is a binary SELinux kernel policy file.
Furthermore, this policy file is rarely the one from AOSP as manufacturers may
add (and they generally do!) a new set of rules to reduce the
attack surface on the services they added.

In order to audit SELinux statements, most of the time, one have to extract
information from the binary policy file using `setools3 utilities (apol,
sesearch, seinfo, sediff, etc.) <https://github.com/TresysTechnology/setools3>`_ for
instance. That work is particularly tedious as these tools output only a
fragment of the ``sepolicy`` file at a time and one may have to juggle with
multiple tools to get an information of the binary file.

To my surprise and to my knowledge, no tool exists to extract a compilable
``policy.conf`` file from a ``sepolicy`` binary [1]_. However, as we have just seen
in the previous section, the SELinux kernel policy is simply a serialized
version of a ``policydb_t`` structure, built from parsing the ``policy.conf``
file.  Moreover, ``checkpolicy`` is able produce a semantically equivalent
binary kernel policy (see :bash:`-b` option) from a compiled kernel policy.
Thus, it should be possible to deserialize an ``sepolicy`` binary and get back
a ``policy.conf`` file equivalent to the original one. 

.. code-block:: bash

    $ checkpolicy -b -M -c 29 -o sepolicy.new sepolicy
    checkpolicy:  loading policy configuration from sepolicy
    libsepol.policydb_index_others: security:  1 users, 2 roles, 534 types, 0 bools
    libsepol.policydb_index_others: security:  1 sens, 1024 cats
    libsepol.policydb_index_others: security:  55 classes, 4473 rules, 0 cond rules
    checkpolicy:  policy configuration loaded
    checkpolicy:  writing binary representation (version 29) to sepolicy.new
    $ sediff -q --stats sepolicy/sepolicy \; sepolicy/sepolicy.new
    $ echo $?
    0

I quickly wrote a proof-of-concept tool called `sedump`_ few weeks ago, using `setools4
<https://github.com/TresysTechnology/setools>`_'s python bindings. As setools4
is still in alpha version and may conflict with setools3, I recommend to run it
inside a docker container:

.. code-block:: bash

    $ sudo apt-get install docker-engine python-pip
    $ sudo pip install docker-compose
    $ git clone https://github.com/ge0n0sis/sedump
    $ cd sedump/docker
    $ docker-compose build master
    $ docker-compose up -d master
    $ docker-compose run master

So far, it has been tested with sepolicy binaries built from AOSP and sepolicy
binaries extracted from Samsung stock ROMs. Currently, binary policies with
conditional access vectors are not working, I am still working on the problem.

.. code-block:: bash

    docker@5534108629ba:~$ cd setools
    docker@5534108629ba:~/setools$ python setup.py develop
    docker@5534108629ba:~/setools$ python sedump sepolicy -o policy.conf

Outside the docker container, one can test that the ``policy.conf`` file is
semantically equivalent to the original one, by compiling it and running a
diffing tool like ``sediff``:

.. code-block:: bash

    $ checkpolicy -M -c 29 -o sepolicy.new policy.conf
    checkpolicy:  loading policy configuration from policy.conf
    checkpolicy:  policy configuration loaded
    checkpolicy:  writing binary representation (version 29) to sepolicy.new
    $ sediff -q --stats sepolicy \; sepolicy.new
    $ echo $?
    0

.. [1] `dispol
       <http://androidxref.com/6.0.0_r1/xref/external/selinux/checkpolicy/test/dispol.c>`_
       currently only displays access vector and conditional access vector rules.

Conclusion
----------

Security Enhancements for Android, and more generally SELinux, is a really
complex subject. In this article, I covered only a tiny part of this solution,
which has been an integral part of the Android security model since Android 4.3.

We have dissected, first, Android's build system to understand how was
generated the SELinux kernel policy binary for Android. The whole build process
is not that different from SELinux for desktops, it heavily uses ``m4`` and
``checkpolicy`` to respectively expand and build a monolithic policy from a set
of SELinux statements. As regular versions of ``m4`` and ``checkpolicy`` are used,
one can build a ``sepolicy`` out of Android source tree easily.

Then, I dug further in the policy compilation process by analyzing the source
code of ``checkpolicy``. We introduced data structures used to store these statements
in memory and I presented briefly the file format of an SELinux kernel policy.
The ``sepolicy`` binary is simply a serialized version of a :cpp:`policydb_t`
structure, built from parsing the ``policy.conf`` file.

Finally, I introduced a proof-of-concept tool, `sedump`_, to decompile or
deserialize a ``sepolicy`` binary into a text file ``policy.conf``, and, to my
surprise, no such tool exists. Once decompiled, one can audit the SELinux
policy the hard way, modify it and compile it to get a new policy file if
needed.

Please note that `sedump`_ is still in alpha-version: do not hesitate to give
us feedbacks or report failing test cases to us via github. A known limitation
is binary policies with conditional access vectors, ``if/else`` statement may
not be correctly rendered. There is a lot of work to do before thinking about
merging it into `setools4 <https://github.com/TresysTechnology/setools>`_'s
mainline.
