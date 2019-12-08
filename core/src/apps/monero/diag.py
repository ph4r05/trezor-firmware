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

            if msg.p1 == 0:
                BPP(None)  # clear old state

            check_mem()
            from apps.monero.xmr import bulletproof as bp
            check_mem("BP Imported")
            from apps.monero.xmr import crypto
            check_mem("Crypto Imported")
            check_mem("+++BP START: %s; %s" % (msg.p1, p2))
            gc.collect()
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

                res = bpi.prove_batch_off(sv, gamma, msg.data3)
                state = bpi.dump_state()
                del(bp, bpi, crypto)
                gc.collect()
                log_trace("BP STATE")
                BPP(state)

            else:
                state = BPP()
                bpi = bp.BulletProofBuilder()
                bpi.load_state(state)
                del(state)
                BPP(None)
                gc.collect()
                log_trace("From state")

                # bp.PRNG = crypto.prng(bp._ZERO)
                bpi.gc_fnc = gc.collect
                bpi.gc_trace = log_trace

                res = bpi.prove_batch_off_step(msg.data3)
                state = bpi.dump_state()
                del(bp, bpi, crypto)
                gc.collect()
                log_trace("BP STATE")
                BPP(state)

            gc.collect()
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
            reps = msg.pd[0] if msg.pd else 1

            from apps.monero.xmr import bulletproof as bp
            check_mem("BP Imported")
            from apps.monero.xmr import crypto
            check_mem("Crypto Imported")

            log_trace('Benchmarking, p1: %s, p2: %s, reps: %s, total: %s' % (p1, p2, reps, p2 * reps))
            gc.collect()

            if p1 == 0:
                a = [crypto.random_scalar() for _ in range(p2)]
                log_trace('random_scalar')

                a1 = [bytearray(32) for i in range(p2)]
                log_trace('alloc bytearray')

                for i in range(p2 * reps):
                    crypto.encodeint_into(a1[i % p2], a[i % p2])
                log_trace('encodeint_into')

                for i in range(p2 * reps):
                    crypto.decodeint_into(a[i % p2], a1[i % p2])
                log_trace('decodeint_into')

                for i in range(p2 * reps):
                    crypto.decodeint_into_noreduce(a[i % p2], a1[i % p2])
                log_trace('decodeint_into_noreduce')

                c = crypto.random_scalar()
                for i in range(p2 * reps):
                    crypto.sc_copy(a[i % p2], c)
                log_trace('sc_copy')

            elif p1 == 1:
                A = [crypto.scalarmult_base(2*i) for i in range(p2)]
                log_trace('scalarmult_base')

                A1 = [bytearray(32) for i in range(p2)]
                log_trace('alloc')

                for i in range(p2 * reps):
                    crypto.encodepoint_into(A1[i % p2], A[i % p2])
                log_trace('encodepoint_into')

                for i in range(p2 * reps):
                    crypto.decodepoint_into(A[i % p2], A1[i % p2])
                log_trace('decodepoint_into')

            elif p1 == 2:
                a = [crypto.random_scalar() for _ in range(p2)]
                A = [crypto.scalarmult_base(2*i) for i in range(p2)]
                B = [crypto.new_point() for i in range(p2)]
                C = crypto.new_point()
                log_trace('generated')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.scalarmult_into(B[i % p2], A[i % p2], a[i % p2])
                log_trace('done-scalarmult_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.scalarmult_base_into(B[i % p2], a[i % p2])
                log_trace('done-scalarmult_base_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.point_add_into(C, C, A[i % p2])
                log_trace('done-point_add_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.point_sub_into(C, C, A[i % p2])
                log_trace('done-point_sub_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.add_keys2_into(C, a[i % p2], a[i % p2], A[i % p2])
                log_trace('done-add_keys2_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.add_keys3_into(C, a[i % p2], A[i % p2], a[i % p2], A[i % p2])
                log_trace('done-add_keys3_into')
                gc.collect()

            elif p1 == 3:
                a = [crypto.random_scalar() for _ in range(p2)]
                log_trace('generated a')

                b = [crypto.random_scalar() for i in range(p2)]
                log_trace('generated b')

                c = crypto.random_scalar()
                log_trace('generated')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.sc_mul_into(c, a[i % p2], b[i % p2])
                log_trace('done-sc_mul_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.sc_muladd_into(c, a[i % p2], b[i % p2], c)
                log_trace('done-sc_muladd_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.sc_mulsub_into(c, a[i % p2], b[i % p2], c)
                log_trace('done-sc_mulsub_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.sc_sub_into(c, a[i % p2], b[i % p2])
                log_trace('done-sc_sub_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.sc_inv_into(c, a[i % p2])
                log_trace('done-sc_inv_into')
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

                for i in range(reps):
                    bp._hadamard_fold(A, crypto.encodeint(a[0]), crypto.encodeint(b[0]))
                log_trace('done-_hadamard_fold')
                gc.collect()

                a1 = [bytearray(32) for i in range(len(a))]
                for i in range(len(a)):
                    crypto.encodeint_into(a1[i % p2], a[i % p2])
                a1 = bp.KeyVWrapped(a1, p2)
                log_trace('encodeint_into')
                gc.collect()

                for i in range(reps):
                    bp._scalar_fold(a1, crypto.encodeint(a[0]), crypto.encodeint(b[0]))
                log_trace('done-_scalar_fold')

            elif p1 == 5:
                b = [bytearray(crypto.random_bytes(32)) for _ in range(p2)]
                log_trace('generated - random_bytes')
                A = [crypto.new_point() for i in range(p2)]
                log_trace('new points new_point()')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.keccak_hash_into(b[i % p2], b[i % p2])
                log_trace('done - keccak_hash_into')
                gc.collect()

                for i in range(p2 * reps):
                    crypto.hash_to_point_into(A[i % p2], b[i % p2])
                log_trace('done - hash_to_point_into')
                gc.collect()

                del(A)
                gc.collect()
                log_trace('pre - gen a')
                a = [crypto.new_scalar() for i in range(p2)]
                log_trace('done - new_scalar')
                for i in range(p2 * reps):
                    crypto.hash_to_scalar_into(a[i % p2], b[i % p2])
                log_trace('done - hash_to_scalar_into')
                gc.collect()


        return retit()
