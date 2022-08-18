import express from "express";
import jwt from "jsonwebtoken";
const app = express();
app.use(express.json())

const users = [
    {
        id: "1",
        username: "Mahafuj",
        password: "mahafuj012",
        isAdmin: true
    },
    {
        id: "2",
        username: "Minhaj",
        password: "minhaj012",
        isAdmin: false
    }
]

let refreshTokens = []

const generateAccessToken= (user) =>{
    return jwt.sign({id: user.id, isAdmin: user.isAdmin}, "secretKey", {expiresIn: "10s"});
}

const generateRefreshToken= (user) =>{
    return jwt.sign({id: user.id, isAdmin: user.isAdmin}, "refreshSecretKey");
}

app.post("/api/refresh", (req, res)=>{
    const refreshToken = req.body.token;

    if(!refreshToken) return res.status(401).json("You are not authenticated.")
    if(!refreshTokens.includes(refreshToken)) return res.status(403).json("Invalid token.")

    jwt.verify(refreshToken, "refreshSecretKey", (err, user)=>{
        err && console.log(err)

        refreshTokens = refreshTokens.filter((token)=> token !== refreshToken);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        refreshTokens.push(newRefreshToken);
        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        })
    })
})

app.post("/api/login", (req, res)=>{
    const {username, password} = req.body;
    const user = users.find((u)=>{
        return username === u.username && password === u.password;
    });

    if(user){
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refreshTokens.push(refreshToken);
        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        });
    }
    else res.status(400).json("username or password incorrect.");
});

const verify = (req, res, next) =>{
    const authHeader = req.headers.authorization;
    if(authHeader){
        const token = authHeader.split(" ")[1];

        jwt.verify(token, "secretKey", (err, user)=>{
            if(err) res.status(403).json("Invalid access token!");
            
            req.user = user;
            next();
        });
    }else{
        res.json("You are not authenticated.")
    }
}

app.delete("/api/users/:id", verify, (req, res)=>{
    if(req.user.id === req.params.id || req.user.isAdmin) res.status(200).json("user has been deleted.");
    else res.status(403).json("Your are not allow to delete this user.");
})



app.listen(8000, ()=>{
    console.log("Backend server is running.")
})