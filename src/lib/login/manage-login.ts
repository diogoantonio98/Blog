import bcrypt from 'bcryptjs';

export async function hashPassword(password: string) {
    const hash = await bcrypt.hash(password, 10);
    //base64 é usado aqui por que .env não consegue ler direito hash
    const base64 = Buffer.from(hash).toString('base64');
    return base64;
}

export async function verifyPassword(password: string, base64Hash: string) {
    const hash = Buffer.from(base64Hash, 'base64').toString('utf-8');
    return bcrypt.compare(password, hash);
}
