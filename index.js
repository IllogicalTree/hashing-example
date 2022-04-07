const bcrypt = require("bcrypt")

const hashPassword = async (password) => await bcrypt.hash(password, 10)
const checkPassword = async (password, hash) => await bcrypt.compare(password, hash)

const main = async () => {
    const password = "password1234"
    const hashedPassword = await hashPassword("password1234");
    const match = await checkPassword(password, hashedPassword);
    console.log(password, hashedPassword, match)
}

main()