# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# load up the simulator w/ indicated list of seed words
from sim_settings import sim_defaults
import stash, chains
from h import b2a_hex
from pincodes import pa
from glob import settings
import stash
from seed import set_seed_value
from utils import xfp2str

tn = chains.BitcoinTestnet

if 1:
    stash.bip39_passphrase = ''
    settings.current = sim_defaults
    settings.overrides.clear()
    settings.set('chain', 'XTN')
    settings.set('words', True)
    settings.set('terms_ok', True)
    settings.set('idle_to', 0)

    import main
    pa.tmp_value = None
    set_seed_value(main.WORDS)

    print("New key in effect: %s" % settings.get('xpub', 'MISSING'))
    print("Fingerprint: %s" % xfp2str(settings.get('xfp', 0)))

    # impt: if going from xprv => seed words, main menu needs updating
    from actions import goto_top_menu
    goto_top_menu()

