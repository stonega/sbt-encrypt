import { argon2d } from 'hash-wasm'
import randomBytes from 'randombytes'
import { Chacha20 } from 'ts-chacha20'

export async function argon2({ password, salt }: Argon2Input): Promise<Buffer> {
	const result = await argon2d({
		password,
		salt, // salt is a buffer containing random bytes
		parallelism: 1,
		iterations: 2,
		memorySize: 32, // use 512KB memory
		hashLength: 32, // output size = 32 bytes
		outputType: 'hex', // return standard encoded string containing parameters needed to verify the key
	})
	return Buffer.from(result, 'hex')
}

function generateRandom(length = 16) {
	return Uint8Array.from(randomBytes(length))
}

export async function encrypt(data: string, password: string) {
	const salt = generateRandom(12)
	const key = await argon2({ password, salt })
	const encrypt = new Chacha20(key, salt).encrypt(Buffer.from(data, 'utf8'))
	const packaged = Buffer.from([...salt, ...encrypt])
	return packaged.toString('base64')
}

export async function decrypt(data: string, password: string) {
	const unpackaged = Buffer.from(data, 'base64')
	const salt = unpackaged.subarray(0, 12)
	const input = unpackaged.subarray(12, data.length)
	const key = await argon2({ password, salt })
	const message = new Chacha20(key, salt).decrypt(input)
	return Buffer.from(message).toString('utf8')
}

type Argon2Input = {
	readonly password: string
	readonly salt: Uint8Array
}
