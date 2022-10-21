import { expect, test } from 'vitest'
import { argon2, decrypt, encrypt } from '../src/index.js'

test('argon2', async () => {
	const key = await argon2({
		password: '121212',
		salt: Buffer.from([158, 82, 111, 126, 245, 222, 179, 76, 133, 117, 16, 149]),
	})
	console.log(JSON.stringify(key))

	expect(key.toString('base64')).toBe(
		'F30DpIwR02Iz7/A+61quxaPTQnqNvcNbFlSs83wZfT4=',
	)
})

test('encrypt data', async () => {
	const data = 'testjkjkljkljjjjjjjjjjjjjjjjjjjjj'
	const encrypted = await encrypt(data, '121212')
	console.log(encrypted)
	const decrypted = await decrypt(encrypted, '121212')
	expect(decrypted).toBe(data)
})

test('decrypt data from dart', async () => {
	const data = 'AHgAtn6KXww8OYouUa6pMw=='
	const decrypted = await decrypt(data, '121212')
	expect(decrypted).toBe('test')
})
