import "dotenv/config";
import "reflect-metadata";
import express from 'express';
import { ApolloServer } from 'apollo-server-express';
import { createConnection } from "typeorm";
import { buildSchema } from "type-graphql";
import { UserResolvers } from "./UserResolver";
import cookieParser from "cookie-parser";
import { verify } from "jsonwebtoken";
import { createAccessToken, createRefreshToken } from "./auth";
import { User } from "./entity/User";
import { sendRefreshToken } from "./sendRefreshToken";

(async () => {
    const app = express();
    app.use(cookieParser());
    app.get('/', (_req, res) => {
        res.send('Hello World!');
    })

    app.post('/refresh_token', async (req, res) => {
        console.log('refresh token request:', req.cookies);
        const token = req.cookies.jid;
        console.log(token);
        if (!token) {
            return { ok: false, accessToken: '' };
        }
        let payload: any = null;
        try {
            payload = verify(token, process.env.REFRESH_TOKEN_SECRET!);
        }catch(err){
            console.log(err);
            return res.send({ ok: false, accessToken: '' });
        }

        // token is valid and we can send back an access token
        const user = await User.findOne({ id: payload.userId });
        if (!user) {
            return res.send({ ok: false, accessToken: '' });
        }

        sendRefreshToken(res, createRefreshToken(user));

        return res.send({ ok: true, accessToken: createAccessToken(user) });
    })
    // console.log(process.env.ACCESS_TOKEN_SECRET);
    // console.log(process.env.REFRESH_TOKEN_SECRET);
    await createConnection();

    const apolloServer = new ApolloServer({
       schema: await buildSchema({
           resolvers: [UserResolvers]
       }),
       context: ({ req, res }) => ({ req, res })
    });

    await apolloServer.start();
    apolloServer.applyMiddleware({ app });

    app.listen(4000, () => {
        console.log("express server started at port 4000");
    });
})();
// createConnection().then(async connection => {

//     console.log("Inserting a new user into the database...");
//     const user = new User();
//     user.firstName = "Timber";
//     user.lastName = "Saw";
//     user.age = 25;
//     await connection.manager.save(user);
//     console.log("Saved a new user with id: " + user.id);

//     console.log("Loading users from the database...");
//     const users = await connection.manager.find(User);
//     console.log("Loaded users: ", users);

//     console.log("Here you can setup and run express/koa/any other framework.");

// }).catch(error => console.log(error));
