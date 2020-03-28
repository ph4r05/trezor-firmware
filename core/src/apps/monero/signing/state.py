import gc
from micropython import const

from trezor import log

from apps.monero.xmr import crypto


MEASURE_STATE = 1

if MEASURE_STATE:
    from apps.monero.xmr.size_counter import *

    _tmp_pt_1 = crypto.new_point()
    _tmp_sc_1 = crypto.new_scalar()

    class TxSizeCounter(SizeCounter):
        def __init__(self, real=False, do_track=True, do_trace=False):
            super().__init__(real, do_track, do_trace)

        def check_type(self, tp, v, name, real):
            c = 0
            if tp == type(_tmp_sc_1):
                c = SIZE_SC if not real else sizeof(v)
            elif tp == type(_tmp_pt_1):
                c = SIZE_PT if not real else sizeof(v)
            else:
                print("Unknown type: ", name, ", v", v, ", tp", tp)
                return 0

            return self.tailsum(c, name, True)


class State:

    STEP_INP = const(100)
    STEP_PERM = const(200)
    STEP_VINI = const(300)
    STEP_ALL_IN = const(350)
    STEP_OUT = const(400)
    STEP_ALL_OUT = const(500)
    STEP_SIGN = const(600)

    def __init__(self, ctx):
        from apps.monero.xmr.keccak_hasher import KeccakXmrArchive
        from apps.monero.xmr.mlsag_hasher import PreMlsagHasher

        self.ctx = ctx

        """
        Account credentials
        type: AccountCreds
        - view private/public key
        - spend private/public key
        - and its corresponding address
        """
        self.creds = None

        # HMAC/encryption keys used to protect offloaded data
        self.key_hmac = None
        self.key_enc = None

        """
        Transaction keys
        - also denoted as r/R
        - tx_priv is a random number
        - tx_pub is equal to `r*G` or `r*D` for subaddresses
        - for subaddresses the `r` is commonly denoted as `s`, however it is still just a random number
        - the keys are used to derive the one time address and its keys (P = H(A*r)*G + B)
        """
        self.tx_priv = None
        self.tx_pub = None

        """
        In some cases when subaddresses are used we need more tx_keys
        (explained in step 1).
        """
        self.need_additional_txkeys = False

        # Connected client version
        self.client_version = 0

        # Bulletproof version. Pre for <=HF9 is 1, for >HP10 is 2
        self.bp_version = 1

        self.input_count = 0
        self.output_count = 0
        self.progress_total = 0
        self.progress_cur = 0

        self.output_change = None
        self.fee = 0

        # wallet sub-address major index
        self.account_idx = 0

        # contains additional tx keys if need_additional_tx_keys is True
        self.additional_tx_private_keys = []
        self.additional_tx_public_keys = []

        # currently processed input/output index
        self.current_input_index = -1
        self.current_output_index = -1
        self.is_processing_offloaded = False

        # for pseudo_out recomputation from new mask
        self.input_last_amount = 0

        self.summary_inputs_money = 0
        self.summary_outs_money = 0

        # output commitments
        self.output_pk_commitments = []

        self.output_amounts = []
        # output *range proof* masks. HP10+ makes them deterministic.
        self.output_masks = []
        # last output mask for client_version=0
        self.output_last_mask = None

        # the range proofs are calculated in batches, this denotes the grouping
        self.rsig_grouping = []
        # is range proof computing offloaded or not
        self.rsig_offload = False

        # sum of all inputs' pseudo out masks
        self.sumpouts_alphas = crypto.sc_0()
        # sum of all output' pseudo out masks
        self.sumout = crypto.sc_0()

        self.subaddresses = {}

        # TX_EXTRA_NONCE extra field for tx.extra, due to sort_tx_extra()
        self.extra_nonce = None

        # contains an array where each item denotes the input's position
        # (inputs are sorted by key images)
        self.source_permutation = []

        """
        Tx prefix hasher/hash. We use the hasher to incrementally hash and then
        store the final hash in tx_prefix_hash.
        See Monero-Trezor documentation section 3.3 for more details.
        """
        self.tx_prefix_hasher = KeccakXmrArchive()
        self.tx_prefix_hash = None

        """
        Full message hasher/hash that is to be signed using MLSAG.
        Contains tx_prefix_hash.
        See Monero-Trezor documentation section 3.3 for more details.
        """
        self.full_message_hasher = PreMlsagHasher()
        self.full_message = None

    def mem_trace(self, x=None, collect=False):
        if __debug__:
            log.debug(
                __name__,
                "Log trace: %s, ... F: %s A: %s",
                x,
                gc.mem_free(),
                gc.mem_alloc(),
            )
        if collect:
            gc.collect()

    def change_address(self):
        return self.output_change.addr if self.output_change else None

    def is_bulletproof_v2(self):
        return self.bp_version >= 2

    def is_det_mask(self):
        return self.bp_version >= 2 or self.client_version > 0

    def dump_size(self):
        if not MEASURE_STATE:
            return

        # STATE_VARS = [
        #     "key_hmac",
        #     "key_enc",
        #     "tx_priv",
        #     "tx_pub",
        #     "need_additional_txkeys",
        #     "client_version",
        #     "bp_version",
        #     "input_count",
        #     "output_count",
        #     "progress_total",
        #     "progress_cur",
        #     "fee",
        #     "account_idx",
        #     "additional_tx_private_keys",
        #     "additional_tx_public_keys",
        #     "current_input_index",
        #     "current_output_index",
        #     "is_processing_offloaded",
        #     "input_last_amount",
        #     "summary_inputs_money",
        #     "summary_outs_money",
        #     "output_pk_commitments",
        #     "output_amounts",
        #     "output_masks",
        #     "output_last_mask",
        #     "rsig_grouping",
        #     "rsig_offload",
        #     "sumpouts_alphas",
        #     "sumout",
        #     "extra_nonce",
        #     "tx_prefix_hash",
        #     "full_message",
        # ]
        #
        # # Manual: creds, tx_prefix_hasher, full_message_hasher, output_change
        #
        # ctr_i = TxSizeCounter(real=False, do_track=False, do_trace=True)
        # ctr_r = TxSizeCounter(real=True, do_track=True, do_trace=True)
        #
        # for ix, x in enumerate(STATE_VARS):
        #     v = getattr(self, x, None)
        #     ctr_i.comp_size(v, x)
        #     ctr_r.comp_size(v, x)
        #
        # if self.creds:
        #     VARS = [
        #         "view_key_private",
        #         "spend_key_private",
        #         "view_key_public",
        #         "spend_key_public",
        #         "address",
        #         "network_type",
        #     ]
        #     isize = ctr_i.slot_sizes(self.creds, VARS, real=False, name="creds")
        #     rsize = ctr_r.slot_sizes(self.creds, VARS, real=True, name="creds")
        #     rsize += sizeof(self.creds)
        #     ctr_i.tailsum(isize, "creds")
        #     ctr_r.tailsum(rsize, "creds")
        #
        # if self.output_change:
        #     rsize = sizeof(self.output_change) + sizeof(self.output_change.addr)
        #     rsize += (
        #         8 + 8 + 8 + 8 + 2 * sizeof(self.output_change.addr.spend_public_key)
        #     )
        #     isize = 1 + 1 + 32 + 32
        #     ctr_i.tailsum(isize, "output_change")
        #     ctr_r.tailsum(rsize, "output_change")
        #
        # HASHER_R_SIZE = (sizeof(_tmp_sc_1) - 9 * 4) + (
        #     8 + 4 + 4 + ((25 * 8) + (24 * 8) + 4 + 4)
        # )
        # HASHER_I_SIZE = (25 * 8) + (24 * 8) + 4 + 4
        # if self.tx_prefix_hasher:
        #     rsize = sizeof(self.tx_prefix_hasher)
        #     rsize += HASHER_R_SIZE
        #     ctr_r.tailsum(rsize, "tx_prefix_hasher")
        #     ctr_i.tailsum(HASHER_I_SIZE, "tx_prefix_hasher")
        #
        # if self.full_message_hasher:
        #     rsize = sizeof(self.full_message_hasher)
        #     rsize += 3 * HASHER_R_SIZE + 8 + sizeof(self.tx_prefix_hasher)
        #     ctr_r.tailsum(rsize, "full_message_hasher")
        #     ctr_i.tailsum(3 * HASHER_I_SIZE + 1, "full_message_hasher")
        #
        # ctr_r.tailsum(sizeof(self), "self")
        # print("!!!!!!!!!!!!!!!!Dump finished: ", ctr_i.acc, ": r: ", ctr_r.acc)
        # ctr_i.report()
        # ctr_r.report()
