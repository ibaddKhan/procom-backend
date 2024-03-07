import mongoose from "mongoose";
import bcrypt from "bcrypt";
import validator from "validator";

const Schema = mongoose.Schema;

const userSchema = new Schema({
  userName: {
    type: String,
    required: true,
    unique: true,
  },
  type: {
    type: String,
    required: true,
  },
  accountnumber: {
    type: Number,
    required: true,
    unique: true,
  },
  phonenumber: {
    type: Number,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: (value) => validator.isEmail(value),
      message: (props) => `${props.value} is not a valid email address`,
    },
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
});

// Pre-save hook to hash the password before saving
userSchema.pre("save", async function (next) {
  const user = this;
  if (user.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(user.password, salt);
    user.password = hash;
  }
  next();
});

// signup method
userSchema.statics.signup = async function (userData) {
  const user = await this.create(userData);
  return user;
};

// login method
userSchema.statics.login = async function (userName, password) {
  if (!userName || !password) {
    throw new Error("User Name and Password are required");
  }

  // finding user in the database
  const user = await this.findOne({ userName });
  if (!user) {
    throw new Error("Incorrect user name");
  }

  // comparing password
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    throw new Error("Incorrect password");
  }
  return user;
};

const User = mongoose.model("Users", userSchema);

export default User;
