import { Session } from './index.js';

const host = 'localhost';
const userName = 'user';
const userPass = 'password';
const domain = 'local';

const winrm = new Session(host, {
    username: userName,
    password: userPass,
}, {
    realm: domain,
});

const res = await winrm.runCmd('powershell', 'Get-ChildItem');
console.log('Command Output:', res.std_out);
