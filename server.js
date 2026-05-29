require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();


app.use(cors());
app.use(express.json());


mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log(err));


const User = mongoose.model("User", {
  name: String,
  email: { type: String, unique: true },
  password: String
});


const Car = mongoose.model("Car", {
  title: String,
  price: Number,
  description: String,
  userId: String
});


const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Not authorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;

    next();

  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

app.get("/", (req, res) => {
  res.send("Backend running");
});


app.post("/signup", async (req, res) => {

  try {

    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        message: "Email already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      email,
      password: hashedPassword
    });

    res.json({
      message: "Signup successful"
    });

  } catch (err) {

    console.log(err);

    res.status(500).json({
      message: "Signup failed"
    });

  }

});


app.post("/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({
        message: "Invalid credentials"
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(400).json({
        message: "Invalid credentials"
      });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email
      }
    });

  } catch (err) {

    console.log(err);

    res.status(500).json({
      message: "Login failed"
    });

  }

});

// ➕ Add Car (Protected)
app.post("/cars", protect, async (req, res) => {

  try {

    const car = await Car.create({
      ...req.body,
      userId: req.user.id
    });

    res.json(car);

  } catch (err) {

    console.log(err);

    res.status(500).json({
      message: "Failed to add car"
    });

  }

});


app.get("/cars", async (req, res) => {

  try {

    const cars = await Car.find();

    res.json(cars);

  } catch (err) {

    console.log(err);

    res.status(500).json({
      message: "Failed to fetch cars"
    });

  }

});


app.get("/cars/:id", async (req, res) => {

  try {

    const car = await Car.findById(req.params.id);

    if (!car) {
      return res.status(404).json({
        message: "Car not found"
      });
    }

    res.json(car);

  } catch (err) {

    console.log(err);

    res.status(500).json({
      message: "Failed to fetch car"
    });

  }

});


app.delete("/cars/:id", protect, async (req, res) => {

  try {

    const car = await Car.findById(req.params.id);

    if (!car) {
      return res.status(404).json({
        message: "Car not found"
      });
    }

    // ✅ Owner Check
    if (car.userId !== req.user.id) {
      return res.status(403).json({
        message: "Not allowed"
      });
    }

    await Car.findByIdAndDelete(req.params.id);

    res.json({
      message: "Car deleted"
    });

  } catch (err) {

    console.log(err);

    res.status(500).json({
      message: "Delete failed"
    });

  }

});


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});