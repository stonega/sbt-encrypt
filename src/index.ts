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
	let encryptedContent = encryptTool.update(data, 'utf8', 'base64')
	encryptedContent += encryptTool.final('base64')
	console.log(encryptedContent)

	const packaged = Buffer.concat([
		iv,
		salt,
		Buffer.from(encryptedContent, 'base64'),
	])
	return packaged.toString('base64')
}

export async function aesDecrypt(data: string, password: string) {
	const unpackaged = Buffer.from(data, 'base64')
	const iv = unpackaged.subarray(0, 16)
	const salt = unpackaged.subarray(16, 32)
	const input = unpackaged.subarray(32)
	const key = await pbkdf2({ password, salt })
	const decryptTool = crypto.createDecipheriv(
		'aes-256-cbc',
		key.subarray(0, 32),
		iv,
	)
	decryptTool.update(
		input.toString('base64'),
		'base64',
		'utf8',
	)
	return decryptTool.final('utf8')
}

type Pbkdf2Input = {
	readonly password: string
	readonly salt: Buffer
}
