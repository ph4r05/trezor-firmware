if __debug__:
    import gc
    import micropython
    import sys

    from trezor import log
    from apps.monero import BPP
    from trezor.messages.DebugMoneroDiagAck import DebugMoneroDiagAck

    PREV_MEM = gc.mem_free()
    CUR_MES = 0

    def log_trace(x=None):
        log.debug(
            __name__,
            "Log trace %s, ... F: %s A: %s, S: %s",
            x,
            gc.mem_free(),
            gc.mem_alloc(),
            micropython.stack_use(),
        )

    def check_mem(x=""):
        global PREV_MEM, CUR_MES

        gc.collect()
        free = gc.mem_free()
        diff = PREV_MEM - free
        log.debug(
            __name__,
            "======= {} {} Diff: {} Free: {} Allocated: {}".format(
                CUR_MES, x, diff, free, gc.mem_alloc()
            ),
        )
        micropython.mem_info()
        gc.collect()
        CUR_MES += 1
        PREV_MEM = free

    def retit(**kwargs):
        return DebugMoneroDiagAck(**kwargs)

    async def diag(ctx, msg, **kwargs):
        log.debug(__name__, "----diagnostics")
        gc.collect()

        if msg.ins == 0:
            check_mem(0)
            return retit()

        elif msg.ins == 1:
            check_mem(1)
            micropython.mem_info(1)
            return retit()

        elif msg.ins == 2:
            log.debug(__name__, "_____________________________________________")
            log.debug(__name__, "_____________________________________________")
            log.debug(__name__, "_____________________________________________")
            return retit()

        elif msg.ins == 3:
            pass

        elif msg.ins == 4:
            total = 0
            monero = 0

            for k, v in sys.modules.items():
                log.info(__name__, "Mod[%s]: %s", k, v)
                total += 1
                if k.startswith("apps.monero"):
                    monero += 1
            log.info(__name__, "Total modules: %s, Monero modules: %s", total, monero)
            return retit()

        elif msg.ins in [5]:
            p1 = msg.p1 if msg.p1 else 1
            check_mem()
            from apps.monero.xmr import bulletproof as bp

            check_mem("BP Imported")
            from apps.monero.xmr import crypto

            check_mem("Crypto Imported")

            bpi = bp.BulletProofBuilder()
            bpi.gc_fnc = gc.collect
            bpi.gc_trace = log_trace

            vals = [crypto.sc_init(137*i) for i in range(16)]
            masks = [crypto.sc_init(991*i) for i in range(16)]
            check_mem("BP pre input")

            bp_res = bpi.prove_batch(vals[:p1], masks[:p1])
            check_mem("BP post prove")

            bpi.verify(bp_res)
            check_mem("BP post verify")
            
            return retit()

        elif msg.ins in [7]:
            global BP
            p2 = msg.p2 if msg.p2 else 2

            check_mem()
            from apps.monero.xmr import bulletproof as bp
            check_mem("BP Imported")
            from apps.monero.xmr import crypto
            check_mem("Crypto Imported")
            check_mem("+++BP START: %s; %s" % (msg.p1, p2))
            log_trace("BP START")

            bpi, res = None, None
            if msg.p1 == 0:
                bp.PRNG = crypto.prng(bp._ZERO)
                bpi = bp.BulletProofBuilder()
                bpi.gc_fnc = gc.collect
                bpi.gc_trace = log_trace
                sv = [crypto.sc_init(137*i) for i in range(p2)]
                gamma = [crypto.sc_init(991*i) for i in range(p2)]

                bpi.off_method = 2 if not msg.pd and len(msg.pd) <= 1 else msg.pd[0]
                if msg.pd and len(msg.pd) >= 4:
                    bpi.nprime_thresh = msg.pd[1]
                    bpi.off2_thresh = msg.pd[2]
                    bpi.batching = msg.pd[3]

                res = bpi.prove_batch_off(sv, gamma)
                BPP(bpi)

            else:
                bpi = BPP()
                bpi.gc_fnc = gc.collect
                bpi.gc_trace = log_trace
                res = bpi.prove_batch_off_step(msg.data3)

            log_trace("BP STEP")
            check_mem("+++BP STEP")
            if isinstance(res, tuple) and res[0] == 1:
                from apps.monero.xmr import serialize
                from apps.monero.xmr.serialize_messages.tx_rsig_bulletproof import Bulletproof2
                B = res[1]
                B2 = Bulletproof2()
                B2.V = B.V
                B2.S = B.S
                B2.A = B.A
                B2.T1 = B.T1
                B2.T2 = B.T2
                B2.taux = B.taux
                B2.mu = B.mu
                B2.L = B.L
                B2.R = B.R
                B2.a = B.a
                B2.b = B.b
                B2.t = B.t
                res = serialize.dump_msg(B2)
                # res = serialize.dump_msg(V=B.V, A=B.A, S=B.S, T1=B.T1, T2=B.T2, taux.B=taux, mu=B.mu, L=B.L, R=B.R, a=B.a, b=B.b, t=B.t))

            ack = DebugMoneroDiagAck()
            if res:
                ack.data3 = res if isinstance(res, (list, tuple)) else [res]
            return ack

        elif msg.ins in [30]:
            check_mem()
            p1 = msg.p1
            p2 = msg.p2 if msg.p2 else 32

            from apps.monero.xmr import bulletproof as bp
            check_mem("BP Imported")
            from apps.monero.xmr import crypto
            check_mem("Crypto Imported")

            if p1 == 0:
                a = [crypto.random_scalar() for _ in range(p2)]
                log_trace('generated')
                a1 = [bytearray(32) for i in range(len(a))]
                log_trace('alloc')
                for i in range(len(a)):
                    crypto.encodeint_into(a1[i], a[i])
                log_trace('converted')
                for i in range(len(a)):
                    crypto.decodeint_into(a[i], a1[i])
                log_trace('converted2')

            elif p1 == 1:
                A = [crypto.scalarmult_base(2*i) for i in range(p2)]
                log_trace('generated')
                A1 = [bytearray(32) for i in range(len(A))]
                log_trace('alloc')
                for i in range(len(A)):
                    crypto.encodepoint_into(A1[i], A[i])
                log_trace('converted')
                for i in range(len(A)):
                    crypto.decodepoint_into(A[i], A1[i])
                log_trace('converted2')

            elif p1 == 2:
                a = [crypto.random_scalar() for _ in range(p2)]
                A = [crypto.scalarmult_base(2*i) for i in range(p2)]
                B = [crypto.new_point() for i in range(p2)]
                C = crypto.new_point()
                log_trace('generated')
                gc.collect()

                for i in range(len(a)):
                    crypto.scalarmult_into(B[i], A[i], a[i])
                log_trace('done-scmult')
                gc.collect()

                for i in range(len(a)):
                    crypto.scalarmult_base_into(B[i], a[i])
                log_trace('done-scmult-b')
                gc.collect()

                for i in range(len(a)):
                    crypto.point_add_into(C, C, A[i])
                log_trace('done-add')
                gc.collect()

                for i in range(len(a)):
                    crypto.add_keys2_into(C, a[i], a[i], A[i])
                log_trace('done-add2')
                gc.collect()

                for i in range(len(a)):
                    crypto.add_keys3_into(C, a[i], A[i], a[i], A[i])
                log_trace('done-add3')
                gc.collect()

            elif p1 == 3:
                a = [crypto.random_scalar() for _ in range(p2)]
                b = [crypto.random_scalar() for i in range(p2)]
                c = crypto.random_scalar()
                log_trace('generated')
                gc.collect()

                for i in range(p2):
                    crypto.sc_mul_into(c, a[i], b[i])
                log_trace('done-mul')
                gc.collect()

                for i in range(p2):
                    crypto.sc_muladd_into(c, a[i], b[i], c)
                log_trace('done-muladd')
                gc.collect()

                for i in range(p2):
                    crypto.sc_sub_into(c, a[i], b[i])
                log_trace('done-scsub')
                gc.collect()

                for i in range(p2):
                    crypto.sc_inv_into(c, a[i])
                log_trace('done-scinv')
                gc.collect()

            elif p1 == 4:
                a = [crypto.random_scalar() for _ in range(p2)]
                b = [crypto.random_scalar() for _ in range(p2)]
                A = [crypto.scalarmult_base(2*i)   for i in range(p2)]
                B = [crypto.scalarmult_base(2*i+1) for i in range(p2)]
                log_trace('generated')
                gc.collect()

                A = [bytearray(crypto.encodepoint(x)) for x in A]
                B = [bytearray(crypto.encodepoint(x)) for x in B]
                A = bp.KeyVWrapped(A, p2)
                B = bp.KeyVWrapped(B, p2)
                a = bp.KeyVWrapped(a, p2, raw=True)
                b = bp.KeyVWrapped(b, p2, raw=True)
                log_trace('converted')
                gc.collect()

                bp._vector_exponent_custom(A, B, None, None, dst=None, a_raw=a, b_raw=b)
                log_trace('done-exp')
                gc.collect()

                bp._hadamard_fold(A, crypto.encodeint(a[0]), crypto.encodeint(b[0]))
                log_trace('done-hfold')
                gc.collect()

                a1 = [bytearray(32) for i in range(len(a))]
                for i in range(len(a)):
                    crypto.encodeint_into(a1[i], a[i])
                a1 = bp.KeyVWrapped(a1, p2)
                log_trace('encoded')
                gc.collect()

                bp._scalar_fold(a1, crypto.encodeint(a[0]), crypto.encodeint(b[0]))
                log_trace('done-scfold')

            elif p1 == 5:
                b = [bytearray(crypto.random_bytes(32)) for _ in range(p2)]
                A = [crypto.new_point() for i in range(p2)]
                log_trace('generated')
                gc.collect()

                for i in range(p2):
                    crypto.keccak_hash_into(b[i], b[i])
                log_trace('done - hash')
                gc.collect()

                for i in range(p2):
                    crypto.hash_to_point_into(A[i], b[i])
                log_trace('done - Hp')
                gc.collect()

                del(A)
                gc.collect()
                a = [crypto.new_scalar() for i in range(p2)]
                for i in range(p2):
                    crypto.hash_to_scalar_into(a[i], b[i])
                log_trace('done - Hs')
                gc.collect()


        return retit()
