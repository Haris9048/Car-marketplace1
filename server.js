require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cloudinary = require("./utils/cloudinary");

const app = express();

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log(err));

// User Model
const User = mongoose.model("User", {
  name: String,
  email: { type: String, unique: true },
  password: String
});

// Car Model
const Car = mongoose.model("Car", {
  title: String,
  price: Number,
  description: String,
  brand: String,
  model: String,
  year: Number,
  fuelType: String,
  imageUrl: String,
  userId: String
});

const upload = multer({
  storage: multer.memoryStorage()
});

// JWT Middleware
const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Not authorized"
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch {
    res.status(401).json({
      message: "Invalid token"
    });
  }
};

// Health Check
app.get("/", (req, res) => {
  res.send("Backend running");
});

// Signup
app.post("/signup", async (req, res) => {

  try {

    const { name, email, password } = req.body;

    if (!name || name.trim()==''){
      return res.status(400).json({
        message : "Name is required"
      })
    }

    if (!email || email.trim() === "") {
  return res.status(400).json({
    message: "Email is required"
  });
}

const emailRegex =
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

if (!emailRegex.test(email)) {
  return res.status(400).json({
    message: "Invalid email"
  });
}

// Password validation
if (!password) {
  return res.status(400).json({
    message: "Password is required"
  });
}

const passwordRegex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

if (!passwordRegex.test(password)) {
  return res.status(400).json({
    message:
      "Password must contain uppercase, lowercase, number and be at least 8 characters"
  });
}

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        message: "Email already exists"
      });
    }

    const hashedPassword =
      await bcrypt.hash(password, 10);

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

// Login
app.post("/login", async (req, res) => {

  try {



    const { email, password } = req.body;

    if (!email || email.trim() === "") {
  return res.status(400).json({
    message: "Email is required"
  });
}

if (!password) {
  return res.status(400).json({
    message: "Password is required"
  });
}

const emailRegex =
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

if (!emailRegex.test(email)) {
  return res.status(400).json({
    message: "Invalid email"
  });
}
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(401).json({
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

// Add Car
app.post("/cars", protect, async (req, res) => {

  if (!req.body.title) {
  return res.status(400).json({
    message: "Title is required"
  });
}

if (!req.body.price || req.body.price <= 0) {
  return res.status(400).json({
    message: "Valid price is required"
  });
}

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

// Get All Cars
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

// Get Single Car
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

// Delete Car
app.delete("/cars/:id", protect, async (req, res) => {

  try {

    const car = await Car.findById(req.params.id);

    if (!car) {
      return res.status(404).json({
        message: "Car not found"
      });
    }

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

app.post("/upload", upload.single("image"), async (req, res) => {

  if (!req.file) {
  return res.status(400).json({
    message: "Image is required"
  });
}

  try {

    const result = await cloudinary.uploader.upload(
      `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`
    );

    res.json({
      imageUrl: result.secure_url
    });

  } catch (err) {

    console.log(err);

    res.status(500).json({
      message: "Upload failed"
    });

  }

});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});