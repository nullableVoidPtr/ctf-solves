E = EllipticCurve(GF(0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd), [0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f, 0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380])

# >>> print(E.trace_of_frobenius())
# 6259259973049303984458607251963156455493393803083893028237

# >>> print(ec.order())
# 30937339651019945892244794266256713890440922455872051984762505561763526780311616863989511376879697740787911484829297

# From FactorDB.com (create time: "Between September 28, 2024, 12:58 pm and September 28, 2024, 12:59 pm" lol)
order_factors = [
	35809,
	46027,
	56369,
	57301,
	65063,
	111659,
	113111,
	7072010737074051173701300310820071551428959987622994965153676442076542799542912293
]

order_factors = order_factors[:-1]

G = E(0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8, 0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182)

order = G.order()

Q_a = E(0x195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499, 0x357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15)
Q_b = E(0xb3e5f89f04d49834de312110ae05f0649b3f0bbe2987304fc4ec2f46d6f036f1a897807c4e693e0bb5cd9ac8a8005f06, 0x85944d98396918741316cd0109929cb706af0cca1eaf378219c5286bdc21e979210390573e3047645e1969bdbcb667eb)

# print("d =", target.log(G))

def pohlig_hellman(target):
	dlogs = []
	for fac in order_factors:
		t = int(order) // int(fac)
		print(f"{fac}:")
		dlog = discrete_log(t*target, t*G, operation="+", bounds=(0, 2**80))
		print(dlog)
		dlogs.append(dlog)

	d = crt(dlogs, order_factors)
	return d

def crack_shared_key():
	d_a = pohlig_hellman(Q_a)
	d_b = pohlig_hellman(Q_b)

	sub_mod = prod(order_factors)

	i = 0
	old_bit_length = 0
	K_a = None
	K_b = None
	while True:
		if i % 1000 == 0:
			print(i)

		dd_a = ((sub_mod * i) + d_a)
		dd_b = ((sub_mod * i) + d_b)
		q_a = G * dd_a
		q_b = G * dd_b

		if q_a == Q_a:
			print("d_a:", dd_a)
			K_a = Q_b * dd_a
			K = K_a
			break

		if q_b == Q_b:
			print("d_b:", dd_b)
			K_b = Q_a * dd_b
			K = K_b
			break

		# if K_a and K_b:
		# 	break

		if dd_a.bit_length() > 0x80 and dd_b.bit_length() > 0x80:
			break

		new_bit_length = max(dd_a.bit_length(), dd_b.bit_length())
		if old_bit_length < new_bit_length:
			print(f"{dd_a.bit_length()=:x} {dd_b.bit_length()=:x}")
			old_bit_length = new_bit_length

		i += 1

	# d_a: 168606034648973740214207039875253762473
	# d_b: 153712271226962757897869155910488792420

	# assert K_a == K_b
	return K

K = crack_shared_key()
# K = E(9285933189458587360370996409965684516994278319709076885861327850062567211786910941012004843231232528920376385508032, 380692327439186423832217831462830789200626503899948375582964334293932372864029888872966411054442434800585116270210)
preimage = K.x().to_bytes()
print(f"{preimage=}")

import hashlib

key = hashlib.sha512(preimage).digest()

from Crypto.Cipher import Salsa20

verify_ct = bytes.fromhex("f272d54c31860f")
verify_pt = b"verify\0"

print(key)

cipher = Salsa20.new(key[:0x20], key[0x20:0x28])
pt = cipher.decrypt(verify_ct)
print(pt)
