let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs');
let path = require('path');

// Dùng public key để verify token RS256
const publicKey = fs.readFileSync(path.join(__dirname, '../keys/public.pem'));

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer ")) {
                return res.status(401).send({ message: "Bạn chưa đăng nhập" });
            }

            let token = req.headers.authorization.split(" ")[1];

            // Verify với public key, chỉ chấp nhận RS256
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

            // Kiểm tra token hết hạn (jwt.verify đã tự throw nếu exp quá hạn)
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                return res.status(401).send({ message: "Người dùng không tồn tại" });
            }

            req.user = user;
            next();

        } catch (error) {
            return res.status(401).send({ message: "Token không hợp lệ hoặc đã hết hạn" });
        }
    }
}