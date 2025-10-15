# Supports BIP32, BIP39, BIP43, BIP44, BIP49, BIP84
# Usage :
# python hd_wallet_keys.py <mnemonic_sentence> <passphrase> <derivation_path> <testnet_flag>
# Tested on Python v3.8.10



########################################################################################################################
####################																				####################
####################									IMPORTS										####################
####################																				####################
########################################################################################################################


import sys
import re

import hmac
import hashlib


# Jimmy Song library
# ------------------
# Modules ecc.py and helper.py from the final version of the sample code from the book :
# Programming Bitcoin by Jimmy Song (2019), O'Reilly Media, ISBN 978-1-492-03149-9
# are required.
# These modules are available at :
# https://github.com/jimmysong/programmingbitcoin/tree/master/code-ch13
# To use the modules download them to your computer and place them in the current directory or place them 
# in another directory and set up the PYTHONPATH environment variable accordingly, eg. :
# export PYTHONPATH="/home/username/Jimmy Song/book-code/code-ch13"
# on Linux (note the double quotes are needed)
# or
# set PYTHONPATH=c:\Jimmy Song\book-code\code-ch13
# on Windows (note double quotes must not be used)
from ecc import S256Point, PrivateKey, N, G
from helper import encode_base58_checksum


# Bech32/Bech32m Python reference implementation
# ----------------------------------------------
# The module segwit_addr.py which is the Bech32/Bech32m Python reference implementation at :
# https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
# is required.
# To use the module download it to your computer and place it in the current directory or place it
# in another directory and set up the PYTHONPATH environment variable accordingly, eg. :
# export PYTHONPATH="/home/username/bech32"
# on Linux (note the double quotes are needed)
# or
# set PYTHONPATH=c:\bech32
# on Windows (note double quotes must not be used)
# For further information see :
# BIP173
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
# and :
# BIP350
# https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
from segwit_addr import encode




########################################################################################################################
####################																				####################
####################									DEFINITIONS									####################
####################																				####################
########################################################################################################################


FIRST_NON_HARDENED_CHILD_INDEX = 0
LAST_NON_HARDENED_CHILD_INDEX = 2 ** 31 - 1

FIRST_HARDENED_CHILD_INDEX = 2 ** 31
LAST_HARDENED_CHILD_INDEX = 2 ** 32 - 1


# Enumeration type to list the various parent derivation path types
class Parent_Derivation_Path_Type(Enum) :
	CUSTOM = 1
	BIP44 = 2
	BIP49 = 3
	BIP84 = 4




########################################################################################################################
####################																				####################
####################									FUNCTIONS									####################
####################																				####################
########################################################################################################################


# Function path_type_to_prefix_type
# ---------------------------------
# Map parent derivation path types to version_prefix_type's suitable for passing into 
# functions base58check_ext_priv_key and base58check_ext_pub_key

def path_type_to_prefix_type(path_type) :
	if (path_type == Parent_Derivation_Path_Type.CUSTOM) :
		return 'bip32/bip44'
	elif (path_type == Parent_Derivation_Path_Type.BIP44) :
		return 'bip32/bip44'
	elif (path_type == Parent_Derivation_Path_Type.BIP49) :
		return 'bip49'
	elif (path_type == Parent_Derivation_Path_Type.BIP84) :
		return 'bip84'



# Function path_type_to_parent_type_text
# --------------------------------------
# Map parent derivation path types to text suitable for display to user

def path_type_to_parent_type_text(path_type) :
	if (path_type == Parent_Derivation_Path_Type.CUSTOM) :
		return 'CUSTOM'
	elif (path_type == Parent_Derivation_Path_Type.BIP44) :
		return 'BIP44'
	elif (path_type == Parent_Derivation_Path_Type.BIP49) :
		return 'BIP49'
	elif (path_type == Parent_Derivation_Path_Type.BIP84) :
		return 'BIP84'



# Function priv_to_pub
# --------------------
# convert 32 byte private key into 33 byte SEC1 compressed public key

def priv_to_pub(priv_key) :
	priv_key_int = int.from_bytes(priv_key, byteorder='big', signed=False)
	return PrivateKey(priv_key_int).point.sec(compressed=True)



# Function priv_to_wif
# --------------------
# convert 32 byte private key into compressed WIF format commencing with 'K' or 'L' for mainnet or 'c' for testnet

def priv_to_wif(priv_key, testnet=False) :
	priv_key_int = int.from_bytes(priv_key, byteorder='big', signed=False)
	return PrivateKey(priv_key_int).wif(compressed=True, testnet=testnet)



# Function hash160
# ----------------
# Perform sha256 hash on input data followed by a ripemd160 hash, producing a 20 byte hash output, as per 
# Mastering Bitcoin 2nd Ed. by Andreas Antonopolous, pg. 65
# Input parameter :
# b = byte array

def hash160(b)
	# There is a constructor method named 'sha256' in the hashlib module but no constructor method 'ripemd160', 
	# so for the latter we have to use the 'new' method. The 'new' method allows data to be pre-populated 
	# in the hash object as the optional second parameter. 
	# The 'digest' method of the hash object returns a byte array.
	return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()



# Function pub_to_p2pkh_address
# -----------------------------
# convert 33 byte SEC1 compressed public key into Base58Check encoded P2PKH address commencing with '1' for mainnet 
# or 'm' or 'n' for testnet

def pub_to_p2pkh_address(pub_key, testnet=False) :
	if testnet:
		version_prefix = bytes.fromhex('6f')
	else:
		version_prefix = bytes.fromhex('00')
	payload = hash160(pub_key)
	return encode_base58_checksum(version_prefix + payload)



# Function pub_to_p2sh_p2wpkh_address
# -----------------------------------
# convert 33 byte SEC1 compressed public key into Base58Check encoded P2SH-P2WPKH address commencing with '3'
# for mainnet or '2' for testnet

def pub_to_p2sh_p2wpkh_address(pub_key, testnet=False) :
	# by BIP141 redeemScript must be exactly a push of the version byte 0x00 plus a push of the 20 byte P2WPKH witness program.
	# The 20 byte P2WPKH witness program is the hash160 of the pub_key.
	# ie. the redeemScript is what would normally appear in the P2WPKH scriptPubKey if we were not wrapping the P2WPKH inside a P2SH.
	redeemScript = bytes.fromhex('0014') + hash160(pub_key)

	if testnet:
		version_prefix = bytes.fromhex('c4')
	else:
		version_prefix = bytes.fromhex('05')
	payload = hash160(redeemScript)
    return encode_base58_checksum(version_prefix + payload)



# Function pub_to_p2wpkh_address
# ------------------------------
# convert 33 byte SEC1 compressed public key into Bech32 encoded P2WPKH address commencing with 'bc1q' for mainnet 
# or 'tb1q' for testnet

def pub_to_p2wpkh_address(pub_key, testnet=False) :
	# set human-readable part
	if testnet :
		hrp = 'tb'
	else :
		hrp = 'bc'

	version_byte = 0
	witness_program = hash160(pub_key)
	bech32_address = encode(hrp, version_byte, witness_program)

	if not bech32_address :
		print('ERROR in function pub_to_p2wpkh_address : failed to construct Bech32 segwit address')
		exit()

	return bech32_address



# Function key_fingerprint
# ------------------------
# calculate the 4 byte BIP32 key fingerprint from the SEC1 compressed public key

def key_fingerprint(pub_key) :
	return hash160(pub_key)[0:4]



# Function base58check_ext_priv_key
# ---------------------------------
#
# Converts a BIP32 ext priv key (priv_key, chain_code) to its Base58Check encoded form in accordance with :
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Serialization_format
#
# Input parameters :
# depth = integer in range 0-255 (0 if master key)
# parent_fingerprint = byte array of length 4 (all zero bytes if master key)
# child_index = integer in range 0 - 2^32-1, the index of the key as a child key (0 if master key)
# chain_code = byte array of length 32
# priv_key = byte array of length 32
# version_prefix_type = 'bip32/bip44' (default), 'bip49', or 'bip84'
# testnet = boolean
#
# Returns :
# Base58Check encoded BIP32 extended private key of the key specified by the input parameters
#
# The choice of parameter version_prefix_type determines the mainnet/testnet version prefixes that will be used in 
# formulating the Base58Check encoded BIP32 ext priv key. These version prefixes are :
# bip32/bip44 :	0x0488ade4/0x04358394 (ie. 0x0488ade4 for mainnet and 0x04358394 for testnet)
# bip49 :		0x049d7878/0x044a4e28
# bip84 :		0x04b2430c/0x045f18bc
# They result in mainnet/testnet ext priv keys with the following prefixes :
# bip32/bip44 :	xprv/tprv (ie. xprv for mainnet and tprv for testnet)
# bip49 :		yprv/uprv
# bip84 :		zprv/vprv
# The choice of version_prefix_type should correspond with the derivation path of the key's parent. This function though 
# does not request what that derivation path is and so cannot check it - the function requests only enough information 
# to construct the Base58Check encoded BIP32 private key. The correct choice of version_prefix_type per derivation
# path type is shown below :-
# Custom derivation path :												'bip32/bip44'
# BIP44 derivation path (of form m/44'/coin_type'/account'/change) :	'bip32/bip44'
# BIP49 derivation path (of form m/49'/coin_type'/account'/change) :	'bip49'
# BIP84 derivation path (of form m/84'/coin_type'/account'/change) :	'bip84'

def base58check_ext_priv_key(depth, parent_fingerprint, child_index, chain_code, priv_key, version_prefix_type = 'bip32/bip44', testnet=False) :

	if version_prefix_type == 'bip32/bip44' :
		if not testnet :
			version_prefix = bytes.fromhex('0488ade4')
		else :
			version_prefix = bytes.fromhex('04358394')
	elif version_prefix_type == 'bip49' :
		if not testnet :
			version_prefix = bytes.fromhex('049d7878')
		else :
			version_prefix = bytes.fromhex('044a4e28')
	elif version_prefix_type == 'bip84' :
		if not testnet :
			version_prefix = bytes.fromhex('04b2430c')
		else :
			version_prefix = bytes.fromhex('045f18bc')

	depth_byte = depth.to_bytes(length=1, byteorder='big', signed=False)

	# note unlike many other places in Bitcoin this integer encoding is big endian
	child_index_bytes = child_index.to_bytes(length=4, byteorder='big', signed=False)

	payload = depth_byte + parent_fingerprint + child_index_bytes + chain_code + b'\x00' + priv_key

	return encode_base58_checksum(version_prefix + payload)



# Function base58check_ext_pub_key
# --------------------------------
#
# Converts a BIP32 ext pub key (pub_key, chain_code) to its Base58Check encoded form in accordance with :
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Serialization_format
#
# Input parameters :
# depth = integer in range 0-255 (0 if master key)
# parent_fingerprint = byte array of length 4 (all zero bytes if master key)
# child_index = integer in range 0 - 2^32-1, the index of the key as a child key (0 if master key)
# chain_code = byte array of length 32
# pub_key = byte array of length 33 containing SEC1 compressed public key
# version_prefix_type = 'bip32/bip44' (default), 'bip49', or 'bip84'
# testnet = boolean
#
# Returns :
# Base58Check encoded BIP32 extended public key of the child key specified by the input parameters
#
# The choice of parameter version_prefix_type determines the mainnet/testnet version prefixes that will be used in 
# formulating the Base58Check encoded BIP32 ext pub key. These version prefixes are :
# bip32/bip44 :	0x0488b21e/0x043587cf (ie. 0x0488b21e for mainnet and 0x043587cf for testnet)
# bip49 :		0x049d7cb2/0x044a5262
# bip84 :		0x04b24746/0x045f1cf6
# They result in mainnet/testnet ext pub keys with the following prefixes :
# bip32/bip44 :	xpub/tpub (ie. xpub for mainnet and tpub for testnet)
# bip49 :		ypub/upub
# bip84 :		zpub/vpub
# The choice of version_prefix_type should correspond with the derivation path of the key's parent. This function though 
# does not request what that derivation path is and so cannot check it - the function requests only enough information 
# to construct the Base58Check encoded BIP32 private key. The correct choice of version_prefix_type per derivation
# path type is shown below :-
# custom derivation path :												'bip32/bip44'
# BIP44 derivation path (of form M/44'/coin_type'/account'/change) :	'bip32/bip44'
# BIP49 derivation path (of form M/49'/coin_type'/account'/change) :	'bip49'
# BIP84 derivation path (of form M/84'/coin_type'/account'/change) :	'bip84'

def base58check_ext_pub_key(depth, parent_fingerprint, child_index, chain_code, pub_key, version_prefix_type = 'bip32/bip44', testnet=False):

	if version_prefix_type == 'bip32/bip44' :
		if not testnet :
			version_prefix = bytes.fromhex('0488b21e')
		else :
			version_prefix = bytes.fromhex('043587cf')
	elif version_prefix_type == 'bip49' :
		if not testnet :
			version_prefix = bytes.fromhex('049d7cb2')
		else :
			version_prefix = bytes.fromhex('044a5262')
	elif version_prefix_type == 'bip84' :
		if not testnet :
			version_prefix = bytes.fromhex('04b24746')
		else :
			version_prefix = bytes.fromhex('045f1cf6')

	depth_byte = depth.to_bytes(length=1, byteorder='big', signed=False)

	# note unlike many other places in Bitcoin this integer encoding is big endian
	child_index_bytes = child_index.to_bytes(length=4, byteorder='big', signed=False)

	payload = depth_byte + parent_fingerprint + child_index_bytes + chain_code + pub_key

	return encode_base58_checksum(version_prefix + payload)



# Function derive_child_ext_priv_key
# ----------------------------------
#
# Produces the BIP32 extended private key (child_priv_key, child_chain_code) for a specified child of a parent extended private key
# (parent_priv_key, parent_chain_code). The child is specified by a child_index in the range [0, 2^32-1] and may be hardened
# or non-hardened.
# Input parameters :
# parent_priv_key = byte array of length 32
# parent_chain_code = byte array of length 32
# child_index = integer in range [0, 2^32-1] specifying the child
# Returns :
# child_priv_key = byte array of length 32
# child_chain_code = byte array of length 32
# or terminates script with an error if an unsuitable hash value arose during the derivation (very low probability event) 
# in which case the child cannot exist for the given child_index.

def derive_child_ext_priv_key(parent_priv_key, parent_chain_code, child_index) :
	parent_priv_key_int = int.from_bytes(parent_priv_key, byteorder='big', signed=False)
	child_index_bytes = child_index.to_bytes(length=4, byteorder='big', signed=False)

	if (child_index >= FIRST_HARDENED_CHILD_INDEX) :
		# hardened derivation
		hmac_output = hmac.new(parent_chain_code, b'\x00' + parent_priv_key + child_index_bytes, 'sha512').digest()
	else :
		# non-hardened derivation
		parent_pub_key = PrivateKey(parent_priv_key_int).point.sec(compressed=True)
		hmac_output = hmac.new(parent_chain_code, parent_pub_key + child_index_bytes, 'sha512').digest()

	hmac_output_left = hmac_output[:32]
	hmac_output_right = hmac_output[32:]
	hmac_output_left_int = int.from_bytes(hmac_output_left, byteorder='big', signed=False)

	# as per BIP32 spec
	if (hmac_output_left_int >= N) :
		print('ERROR in function derive_child_ext_priv_key : an unsuitable hash value arose during the derivation, use a different child index')
		exit()

	child_priv_key_int = (hmac_output_left_int + parent_priv_key_int) % N
	if (child_priv_key_int == 0) :
		# zero is not permissable as a private key
		print('ERROR in function derive_child_ext_priv_key : an unsuitable hash value arose during the derivation, use a different child index')
		exit()

	child_priv_key = child_priv_key_int.to_bytes(length=32, byteorder='big', signed=False)
	child_chain_code = hmac_output_right

	return (child_priv_key, child_chain_code)



# Function derive_child_ext_pub_key
# ---------------------------------
#
# Produces the BIP32 extended public key (child_pub_key, child_chain_code) for a specified child of a parent extended public key
# (parent_pub_key, parent_chain_code). The child is specified by a child_index in the range [0, 2^32-1], however the function
# will fail if the child is hardened.
# Input parameters :
# parent_pub_key = byte array of length 33 containing SEC1 compressed public key
# parent_chain_code = byte array of length 32
# child_index = integer in range [0, 2^32-1] specifying the child
# Returns :
# child_pub_key = byte array of length 33 containing SEC1 compressed public key
# child_chain_code = byte array of length 32
# or terminates script with an error if either :
# (1) child_index >= HARDENED_INDEX_BEGIN, ie. a hardened child (the requested extended pub key derivation is then not possible), or
# (2) an unsuitable hash value arises during the derivation (very low probability event) in which case the child cannot exist for 
# the given child_index.

def derive_child_ext_pub_key(parent_pub_key, parent_chain_code, child_index) :
	child_index_bytes = child_index.to_bytes(length=4, byteorder='big', signed=False)

	if (child_index >= FIRST_HARDENED_CHILD_INDEX) :
		# hardened child, requested extended pub key derivation not possible
		print("ERROR in function derive_child_ext_pub_key : public parent key to public child key derivation not possible for hardened child")
		exit()
	else :
		# non-hardened derivation
		hmac_output = hmac.new(parent_chain_code, parent_pub_key + child_index_bytes, 'sha512').digest()

	hmac_output_left = hmac_output[:32]
	hmac_output_right = hmac_output[32:]
	hmac_output_left_int = int.from_bytes(hmac_output_left, byteorder='big', signed=False)

	# as per BIP32 spec
	if (hmac_output_left_int >= N) :
		print('ERROR in function derive_child_ext_pub_key : an unsuitable hash value arose during the derivation, use a different child index')
		exit()

	child_pub_key_point = (hmac_output_left_int*G) + S256Point.parse(parent_pub_key) 
	if (child_pub_key_point.x is None) :
		# ie. child_pub_key_point is point at infinity on the elliptic curve (this means the associated 
		# private key for this pub key is zero, which is an invalid value for a private key)
		print('ERROR in function derive_child_ext_pub_key : an unsuitable hash value arose during the derivation, use a different child index')
		exit()

	child_pub_key = child_pub_key_point.sec(compressed=True)
	child_chain_code = hmac_output_right

	return (child_pub_key, child_chain_code)



# Function get_parent_type
# ------------------------
#
# Accepts the list parent_path_components from function derivation_path_ext_key (so all elements in the list beyond the first
# are child indices in integer form) and determines whether this parent's derivation path conforms with BIP44, BIP49, BIP84, or 
# none of these. In the latter case the parent derivation path type is classed as 'CUSTOM'.

def get_parent_type(parent_path_components) :
	if len(parent_path_components) != 5) :
		return Parent_Derivation_Path_Type.CUSTOM

	if	(	parent_path_components[1] >= FIRST_HARDENED_CHILD_INDEX and parent_path_components[1] <= LAST_HARDENED_CHILD_INDEX 	and
			parent_path_components[2] >= FIRST_HARDENED_CHILD_INDEX and parent_path_components[2] <= LAST_HARDENED_CHILD_INDEX 	and
			parent_path_components[3] >= FIRST_HARDENED_CHILD_INDEX and parent_path_components[3] <= LAST_HARDENED_CHILD_INDEX 	and
			parent_path_components[4] >= FIRST_NON_HARDENED_CHILD_INDEX and parent_path_components[4] <= FIRST_NON_HARDENED_CHILD_INDEX + 1) :
		if parent_path_components[1] == FIRST_HARDENED_CHILD_INDEX + 44
			return Parent_Derivation_Path_Type.BIP44
		elif parent_path_components[1] == FIRST_HARDENED_CHILD_INDEX + 49
			return Parent_Derivation_Path_Type.BIP49
		elif parent_path_components[1] == FIRST_HARDENED_CHILD_INDEX + 84
			return Parent_Derivation_Path_Type.BIP84
		else :
			return Parent_Derivation_Path_Type.CUSTOM
	else :
		return Parent_Derivation_Path_Type.CUSTOM



# Function derivation_path_ext_key
# --------------------------------
#
# For the specified derivation path returns a BIP32 extended private key (priv_key, chain_code) or BIP32 extended
# public key (pub_key, chain_code) plus ancillary information relating to the key. The derivation commences at the master key 
# denoted by 'm' (master private key) or 'M' (master public key). Assumes the global variables master_priv_key,
# master_pub_key, and master_chain_code have been populated.
# Checks if derivation_path is of the correct format, terminating the script with an error if it is not. 
# The correct format is as described in Mastering Bitcoin 2nd Ed. by Andreas Antonopolous, pg. 113. Or as described in :
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-The_key_tree 
# except with the child index number for a hardened child denoted by the suffixed prime character ' rather than
# the subscript H.
# Returns :
# (depth, parent_fingerprint, child_index, chain_code, key, parent_type)
# ie. as the 1st 5 parameters to functions base58check_ext_priv_key/base58check_ext_pub_key, plus the parent_type

def derivation_path_ext_key(derivation_path) :
	path_components = derivation_path.split('/')

	no_of_path_components = len(path_components)

	# check first path component is valid - must be 'm' or 'M'
	if (path_components[0] != 'm' and path_components[0] != 'M') :
		print("ERROR in function derivation_path_ext_key : First component in HD wallet derivation path must be 'm' or 'M'")
		exit()

	# check all path components beyond the first are valid and convert them to child index integers. Exit script 
	# with an error if an invalid format component is detected. Loop is not entered if there is only one path component.
	for i in range(1, no_of_path_components) :
		if (path_components[i].isdecimal()) :
			# non-hardened child index
			path_components[i] = int(path_components[i])
			if not (path_components[i] >= FIRST_NON_HARDENED_CHILD_INDEX and path_components[i] <= LAST_NON_HARDENED_CHILD_INDEX) :
				print("ERROR in function derivation_path_ext_key : non-hardened child index '{}' is out of range".format(path_components[i]))
				exit()
		else :
			match = re.search("(^\d+)'$", path_components[i])
			if (match) :
				# hardened child index
				path_components[i] = int(match.group(1)) + FIRST_HARDENED_CHILD_INDEX
				if not (path_components[i] >= FIRST_HARDENED_CHILD_INDEX and path_components[i] <= LAST_HARDENED_CHILD_INDEX) :
					print("ERROR in function derivation_path_ext_key : hardened child index '{}' is out of range".format(path_components[i]))
					exit()
			else :
				print("ERROR in function derivation_path_ext_key : invalid child index '{}' in HD wallet key path".format(path_components[i]))
				exit()

	depth = no_of_path_components - 1
	if depth > 0 :
		parent_path_components = path_components[:depth]
		parent_type = get_parent_type(parent_path_components)
	else :
		# for code clarity the case of depth == 0 is handled within the if branches below
		pass

	if (path_components[0] == 'm') :
		# private key derivation sequence
		# commence at the master extended private key
		(priv_key, chain_code) = (master_priv_key, master_chain_code)
		# check for case of master key path - no derivations needed
		if depth == 0 :
			return (0, bytes.fromhex('00000000'), 0, chain_code, priv_key, Parent_Derivation_Path_Type.CUSTOM)
		# derive down to the parent so we can get its fingerprint
		for i in range(1, depth) :
			# note loop is never entered if only two path components
			child_index = path_components[i]
			(priv_key, chain_code) = derive_child_ext_priv_key(priv_key, chain_code, child_index)
		parent_fingerprint = key_fingerprint(priv_to_pub(priv_key))
		# do final derivation to the required key
		child_index = path_components[depth]
		(priv_key, chain_code) = derive_child_ext_priv_key(priv_key, chain_code, child_index)
		return (depth, parent_fingerprint, child_index, chain_code, priv_key, parent_type)
	elif (path_components[0] == 'M') :
		# public key derivation sequence
		# commence at the master extended public key
		(pub_key, chain_code) = (master_pub_key, master_chain_code)
		# check for case of master key path - no derivations needed
		if depth == 0 :
			return (0, bytes.fromhex('00000000'), 0, chain_code, pub_key, Parent_Derivation_Path_Type.CUSTOM)
		# derive down to the parent so we can get its fingerprint
		for i in range(1, depth) :
			# note loop is never entered if only two path components
			child_index = path_components[i]
			if (child_index >= FIRST_HARDENED_CHILD_INDEX) :
				# hardened child, so public parent key to public child key derivation not possible
				print("ERROR in function derivation_path_ext_key : public parent key to public child key derivation not possible for hardened child index {}'".format(path_components[i] - FIRST_HARDENED_CHILD_INDEX))
				exit()
			(pub_key, chain_code) = derive_child_ext_pub_key(pub_key, chain_code, child_index)
		parent_fingerprint = key_fingerprint(pub_key)
		# do final derivation to the required key
		child_index = path_components[depth]
		(pub_key, chain_code) = derive_child_ext_pub_key(pub_key, chain_code, child_index)
		return (depth, parent_fingerprint, child_index, chain_code, pub_key, parent_type)



# Function compute_seed
# ---------------------
#
# Computes BIP39 seed.
# Input parameters :
# mnemonic_sentence = BIP38 mnemonic sentence, ie. the space separated mnemonic words concatenated into a single text string,
# passphrase = optional passphrase as a text string.
# As specified in BIP39 the mnemonic sentence may comprise 12, 15, 18, 21, or 24 words depending on the initial entropy 
# length (128 - 256 bits) that was used to derive the word list.
# Returns :
# The 512 bit (64 byte) seed generated from the input parameters by the PBKDF2 key derivation function

def compute_seed(mnemonic_sentence, passphrase='') :
	kdf_hash_name = 'sha512'
	kdf_password = mnemonic_sentence.encode()
	kdf_salt = b'mnemonic' + passphrase.encode()
	kdf_iterations = 2048
	return hashlib.pbkdf2_hmac(kdf_hash_name, kdf_password, kdf_salt, kdf_iterations)




########################################################################################################################
####################																				####################
####################								MAIN PROGRAM									####################
####################																				####################
########################################################################################################################


mnemonic_sentence = sys.argv[1]
passphrase = sys.argv[2]
derivation_path = sys.argv[3]
testnet_flag = sys.argv[4]

# set defaults
if not mnemonic_sentence :
	mnemonic_sentence = 'fit crunch census knee piano sail logic fiber purchase over obvious describe'
if not passphrase :
	passphrase = ''

if int(testnet_flag) :
	testnet = True
else :
	testnet = False



seed = compute_seed(mnemonic_sentence, passphrase)

# compute master key as described in BIP32 :
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Master_key_generation
# Also described in Mastering Bitcoin 2nd Ed. by Andreas Antonopolous, pg. 106
hashed_seed = hmac.new(key=b'Bitcoin seed', msg=seed, digestmod='sha512').digest()
master_priv_key = hashed_seed[:32]
master_chain_code = hashed_seed[32:]
master_pub_key = priv_to_pub(master_priv_key)



# Compute the required key. This function will terminate the script with an error if derivation_path 
# is not a valid form.
(depth, parent_fingerprint, child_index, chain_code, key, parent_type) = derivation_path_ext_key(derivation_path)

version_prefix_type = path_type_to_prefix_type(parent_type)
parent_type_text = path_type_to_parent_type_text(parent_type)

if (len(key) == 32) :
	# private key - the same Base58Check encoded WIF private key is provided irrespective of the parent_type
	# but the Base58Check encoded extended private key provided varies depending on the parent_type
	print('Private key : {}'.format(priv_to_wif(key, testnet)))
	print('Detected parent type : {}'.format(parent_type_text))
	ext_priv_key = base58check_ext_priv_key(depth, parent_fingerprint, child_index, chain_code, key, version_prefix_type, testnet)
	print('Extended private key : {}'.format(ext_priv_key))
else :
	# public key - we provide the address corresponding to the 33 byte long SEC1 compressed public key,
	# this address being of the appropriate type (ie. P2PKH, P2SH-P2WPKH, or P2WPKH) depending on the parent_type,
	# and we provide the Base58Check encoded extended public key which also varies depending on the parent_type
	if parent_type == Parent_Derivation_Path_Type.CUSTOM :
		# parent derivation path type is custom type,
		# so display the Base58Check encoded P2PKH address for the public key
		print('Address : {}'.format(pub_to_p2pkh_address(key, testnet)))
	elif parent_type == Parent_Derivation_Path_Type.BIP44 :
		# parent derivation path type is BIP44 type, ie. M/44'/coin_type'/account'/change,
		# so display the Base58Check encoded P2PKH address for the public key
		print('Address : {}'.format(pub_to_p2pkh_address(key, testnet)))
	elif parent_type == Parent_Derivation_Path_Type.BIP49 :
		# parent derivation path type is BIP49 type, ie. M/49'/coin_type'/account'/change,
		# so display the Base58Check encoded P2SH-P2WPKH address for the public key
		print('Address : {}'.format(pub_to_p2sh_p2wpkh_address(key, testnet)))
	elif parent_type == Parent_Derivation_Path_Type.BIP84 :
		# parent derivation path type is BIP84 type, ie. M/84'/coin_type'/account'/change,
		# so display the Bech32 encoded P2WPKH address for the public key
		print('Address : {}'.format(pub_to_p2wpkh_address(key, testnet)))
	print('Detected parent type : {}'.format(parent_type_text))
	ext_pub_key = base58check_ext_pub_key(depth, parent_fingerprint, child_index, chain_code, key, version_prefix_type, testnet)
	print('Extended public key : {}'.format(ext_pub_key))

