//caso queira gerar senhas hash

import { hashPassword } from '@/lib/login/manage-login';

(async () => {
    const minhaSenha = 'qualquer coisa'; // NÃO ESQUECER DE APAGAR SUA SENHA DAQUI
    const hashDaSuaSenhaEmBase64 = await hashPassword(minhaSenha);

    console.log({ hashDaSuaSenhaEmBase64 });
})();
