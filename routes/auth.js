var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let fs = require('fs');
let path = require('path');
const { CheckLogin } = require("../utils/authHandler");
const { body, validationResult } = require('express-validator');

// Đọc cặp khóa RSA từ file
const privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.pem'));
const publicKey  = fs.readFileSync(path.join(__dirname, '../keys/public.pem'));

// ─── REGISTER ────────────────────────────────────────────────────────────────
router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(
            username, password, email, "69b0ddec842e41e8160132b8"
        );
        res.send(newUser);
    } catch (error) {
        res.status(400).send({ message: error.message });
    }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);

        if (!user) {
            return res.status(401).send({ message: "Thông tin đăng nhập sai" });
        }

        if (user.lockTime && user.lockTime > Date.now()) {
            return res.status(403).send({ message: "Tài khoản đang bị khóa, thử lại sau" });
        }

        if (bcrypt.compareSync(password, user.password)) {
            // Reset loginCount khi đăng nhập thành công
            user.loginCount = 0;
            await user.save();

            // Ký token bằng RS256 với private key
            let token = jwt.sign(
                { id: user._id },
                privateKey,
                {
                    algorithm: 'RS256',
                    expiresIn: '1h'
                }
            );
            res.send({ token });

        } else {
            user.loginCount++;
            if (user.loginCount >= 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000; // khóa 1 giờ
            }
            await user.save();
            return res.status(401).send({ message: "Thông tin đăng nhập sai" });
        }

    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

// ─── ME ───────────────────────────────────────────────────────────────────────
router.get('/me', CheckLogin, function (req, res, next) {
    res.send(req.user);
});

// ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────
// Validate newPassword phải đủ mạnh
const changePasswordValidator = [
    body('oldPassword')
        .notEmpty().withMessage('oldPassword không được để trống'),

    body('newPassword')
        .notEmpty().withMessage('newPassword không được để trống')
        .bail()
        .isStrongPassword({
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        })
        .withMessage('newPassword phải có ít nhất 8 ký tự, gồm 1 hoa, 1 thường, 1 số, 1 ký tự đặc biệt')
];

router.put('/change-password', CheckLogin, changePasswordValidator, async function (req, res, next) {
    // Kiểm tra lỗi validate
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(
            errors.array().map(e => ({ [e.path]: e.msg }))
        );
    }

    try {
        let { oldPassword, newPassword } = req.body;
        let user = req.user; // đã được gắn bởi CheckLogin

        // Kiểm tra oldPassword có đúng không
        const isMatch = bcrypt.compareSync(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).send({ message: "Mật khẩu cũ không chính xác" });
        }

        // Không cho đặt lại mật khẩu giống cũ
        const isSame = bcrypt.compareSync(newPassword, user.password);
        if (isSame) {
            return res.status(400).send({ message: "Mật khẩu mới không được trùng mật khẩu cũ" });
        }

        // Cập nhật password (pre-save hook sẽ tự hash)
        user.password = newPassword;
        await user.save();

        res.send({ message: "Đổi mật khẩu thành công" });

    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

module.exports = router;