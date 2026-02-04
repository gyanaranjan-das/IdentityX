import User from "./auth.schema.js";

const findUserByEmail = (email) => {
    return User.findOne({
        email
    }).select("+password");
}

const createUser = (data) => {
    return User.create(data);
}

export {
    findUserByEmail,
    createUser
}