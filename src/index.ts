import crypto, { pbkdf2 as deriveKey } from 'node:crypto'
export function pbkdf2({ password, salt }: Pbkdf2Input): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		deriveKey(password, salt, 1, 64, 'sha256', (error, key) => {
			if (error) return reject(error)
			resolve(key)
		})
	})
}

function generateRandom() {
	return Buffer.from(crypto.randomBytes(16))
}

export async function aesEncrypt(data: string, password: string) {
	const salt = generateRandom()
	const iv = generateRandom()
	const key = await pbkdf2({ password, salt })
	const encryptTool = crypto.createCipheriv(
		'aes-256-cbc',
		key.subarray(0, 32),
		iv,
	)
	let content = encryptTool.update(data, 'ascii', 'base64')
	content += encryptTool.final('base64')
	const packaged = Buffer.concat([
		iv,
		salt,
		Buffer.from(content, 'base64'),
	])
	return packaged.toString('base64')
}

export async function aesDecrypt(data: string, password: string) {
	const unpackaged = Buffer.from(data, 'base64')
	const iv = unpackaged.subarray(0, 16)
	const salt = unpackaged.subarray(16, 32)
	const input = unpackaged.subarray(32, data.length)
	const key = await pbkdf2({ password, salt })
	const decryptTool = crypto.createDecipheriv(
		'aes-256-cbc',
		key.subarray(0, 32),
		iv,
	)
	const result = decryptTool.update(input.toString('base64'), 'base64', 'ascii')
	return result + decryptTool.final('ascii')
}

type Pbkdf2Input = {
	readonly password: string
	readonly salt: Buffer
}
