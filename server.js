const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')

const app = express()
app.use(express.json())
app.use(cors())
require('dotenv').config()

const uri = process.env.MONGOOSE_URI
const port = process.env.PORT

const adminSchema = {
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  mobile: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
}

const gallerySchema = {
  name: {
    type: String,
    required: true,
  },
  imageUrl: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
}

const commentsSchema = {
  comment: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
}

const contactSchema = {
  name: {
    type: String,
    required: true,
  },
  contact: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
}

const Admin = mongoose.model('Admin', adminSchema)
const Gallery = mongoose.model('Gallery', gallerySchema)
const Comment = mongoose.model('Comments', commentsSchema)
const Contact = mongoose.model('Contacts', contactSchema)

const connectDatabase = async () => {
  try {
    await mongoose.connect(uri, { autoCreate: true })
    console.log('database connected')
    app.listen(port || 3008, () => {
      console.log(`Connected to the port ${port || 3008}`)
    })
  } catch (e) {
    console.error('error in connecting to database', e.message)
    process.exit(1)
  }
}

//middleware for authentication
const tokenAuthentication = (req, res, next) => {
  const authHeader = req.header('Authorization')

  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized: Access token missing' })
  }

  try {
    // Extracting the token and removing the "Bearer " prefix
    const token = authHeader.split(' ')[1]

    if (!token) {
      return res
        .status(401)
        .json({ error: 'Unauthorized: Invalid token format' })
    }

    const validToken = jwt.verify(token, process.env.MY_SECRET_CODE)

    if (validToken) {
      req.details = req.body
      next()
    } else {
      res.status(401).json({ error: 'Unauthorized: Invalid token' })
    }
  } catch (error) {
    console.error('Error in token authentication:', error.message)
    res.status(403).json({ error: 'Forbidden: Error in token authentication' })
  }
}

//admin signup
app.post('/admin/signup', async (req, res) => {
  const { name, mobile, email, password } = req.body

  try {
    // Checking if an admin with the given email or mobile already exists
    const existingAdmin = await Admin.findOne({
      $or: [{ mobile: mobile }, { email: email }],
    })

    if (existingAdmin) {
      return res.status(409).json({ error: 'email or mobile already used.' })
    }

    // Hashing the password for security
    const hashedPass = await bcrypt.hash(password, 10)

    // No existing admin found, creating the new admin
    const newAdmin = new Admin({
      name,
      mobile,
      email,
      password: hashedPass,
    })

    // Saving the new admin to the database
    await newAdmin.save()

    return res.status(201).json({ message: 'admin created successfully.' })
  } catch (error) {
    console.error('error in admin signup:', error.message)
    return res.status(500).json({ error: 'internal server error.' })
  }
})

//admin login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body

  try {
    const existingAdmin = await Admin.findOne({
      $or: [{ mobile: username }, { email: username }],
    })

    if (existingAdmin) {
      const validPass = await bcrypt.compare(password, existingAdmin.password)

      if (validPass) {
        // Generating JWT token
        const payload = { id: existingAdmin._id, username: username }
        const token = jwt.sign(payload, process.env.MY_SECRET_CODE, {
          expiresIn: '1h',
        })
        // Sending the token in the response
        return res.status(200).json({ jwtToken: token })
      } else {
        return res.status(401).json({ error: 'invalid password.' })
      }
    } else {
      return res.status(404).json({ error: 'admin not found.' })
    }
  } catch (error) {
    console.error('error in admin login:', error.message)
    return res.status(500).json({ error: 'internal server error.' })
  }
})

//add image to gallery
app.post('/gallery', tokenAuthentication, async (req, res) => {
  const { name, imageUrl } = req.details

  try {
    // creating new image details
    const newImage = new Gallery({
      name,
      imageUrl,
    })

    // saving to the gallery
    const savedImage = await newImage.save()

    // responding with a success message
    res.status(201).json({
      message: 'image details added successfully.',
      imageId: savedImage._id,
    })
  } catch (error) {
    console.error('error in adding image details:', error.message)
    res.status(500).json({ error: 'internal server error.' })
  }
})

//remove image from gallery
app.delete('/gallery', tokenAuthentication, async (req, res) => {
  const { imageName } = req.details

  try {
    // Checking if the image with the given name exists
    const existingImage = await Gallery.findOne({ name: imageName })
    if (!existingImage) {
      return res.status(404).json({ error: 'image not found' })
    }
    // deleting the image
    await Gallery.findOneAndDelete({ name: imageName })

    // responding with a success message
    res.status(200).json({ message: 'image deleted successfully' })
  } catch (error) {
    console.error('error in deleting image:', error.message)
    res.status(500).json({ error: 'internal server error' })
  }
})

//get all images
app.get('/gallery', async (req, res) => {
  try {
    // getting all images
    const allImages = await Gallery.find()

    // sending the list of images
    res.status(200).json({ images: allImages })
  } catch (error) {
    console.error('error in fetching all images:', error.message)
    res.status(500).json({ error: 'internal server error.' })
  }
})

//send comment
app.post('/comment', async (req, res) => {
  const { comment } = req.body
  try {
    //creating the comment
    const newComment = new Comment({
      comment,
    })

    //adding the comment to database
    await newComment.save()
    res.status(201).json({ message: 'Your response received successfully' })
  } catch (e) {
    res.status(500).json({ message: 'error in sending your response' })
  }
})

//view comments
app.get('/comments', async (req, res) => {
  try {
    // getting all comments from the database and sorting them in desc order or received
    const allComments = await Comment.find().sort({ createdAt: -1 })

    // responding with the array of comments
    res.status(200).json({ comments: allComments })
  } catch (error) {
    res.status(500).json({ error: 'internal server error' })
  }
})

//add contact details
app.post('/contact', tokenAuthentication, async (req, res) => {
  const { name, contact } = req.details
  try {
    //creating new contact
    const newContact = new Contact({
      name,
      contact,
    })

    //saving the contact
    await newContact.save()
    res.status(201).json({ message: 'your details received successfully' })
  } catch (e) {
    res.status(500).json({ message: 'error in sending your details' })
  }
})

//get contacts
app.get('/contact', async (req, res) => {
  try {
    // getting all contacts from the database and sorting them in desc order or received
    const allComments = await Contact.find().sort({ createdAt: -1 })

    // responding with the array of contacts
    res.status(200).json({ contacts: allComments })
  } catch (error) {
    res.status(500).json({ error: 'internal server error' })
  }
})

//admin password resetting
let generatedOtp = ''
let userMail = ''

app.post('/reset-password', async (req, res) => {
  try {
    const { email } = req.body
    const mail = process.env.MAIL
    const password = process.env.MAIL_PASS

    // Checking if the admin with the provided email exists
    const existingAdmin = await Admin.findOne({ email })

    if (!existingAdmin) {
      return res.status(404).json({ error: 'Details not found.' })
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: mail,
        pass: password,
      },
    })

    // Generating a new OTP
    generatedOtp = Math.floor(10000000 + Math.random() * 90000000)
    userMail = email

    const mailOptions = {
      from: mail,
      to: email,
      subject: 'Reset your password',
      text: `OTP for resetting your password is ${generatedOtp}\n\n OTP is valid for 10 minutes`,
    }

    // Sending the email with OTP
    const send = await transporter.sendMail(mailOptions)

    // Setting a timeout to reset the OTP after 10 minutes
    setTimeout(() => {
      generatedOtp = ''
      userMail = ''
    }, 10 * 60 * 1000)

    res.status(201).json({
      message:
        'OTP sent to your email address. Check your spam folder as well.',
    })
  } catch (error) {
    console.error('Error sending OTP:', error.message)
    res.status(500).json({ error: 'Internal server error.' })
  }
})

//otp verification
app.post('/otp-verification', async (req, res) => {
  const { otp, password } = req.body
  try {
    if (otp === generatedOtp) {
      // otp matched
      const admin = await Admin.findOne({ email: userMail })
      //hashing the password
      const hashedPass = await bcrypt.hash(password, 10)
      //updating and saving the password
      admin.password = hashedPass
      await admin.save()
      generatedOtp = ''
      userMail = ''
      res.status(201).json({ message: 'Password updated successfully' })
    } else {
      res.status(401).json({ message: 'Invalid otp' })
    }
  } catch (e) {
    res.status(500).json({ message: 'internal server error' })
  }
})

connectDatabase()
