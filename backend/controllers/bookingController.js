import { catchAsyncErrors } from '../middleware/catchAsyncErrors.js';
import ErrorHandler from '../middleware/error.js';
import Accommodation from '../models/Admin.model.js';
import Booking from '../models/Booking.model.js';
import mongoose  from 'mongoose';
import { config } from 'dotenv';
import Razorpay from 'razorpay';
import crypto from 'crypto'
import Payment from '../models/Payment.model.js';
import RefundRequest from '../models/RefundRequest.model.js';
import { sendEmail } from '../utils/emailService.js';
import { saveTempBooking,getTempBooking,deleteTempBooking} from '../utils/tempBookings.js';
import {getBookedSeatsForDate} from "../helper/capacity.js";
import {autoCompleteBookings} from "../services/bookingService.js"

import { v4 as uuidv4 } from 'uuid';

config({
  path:'./config/config.env'
});

const razorpay = new Razorpay({
  key_id:process.env.RAZORPAY_KEY_ID,
  key_secret:process.env.RAZORPAY_KEY_SECRET
});

export const createBookingOrder = async (req, res, next) => {
  try {
    const { accommodationId } = req.params;
 
    const {
      stayDate,
      groupSize,
      mealType,
      needStay,
      stayNight,
      amount,
      groupName,
      paymentMode,
      name,
      email,
      phone
    } = req.body;
console.log("body: ",req.body);
  

    // Validation
    if (!stayDate || !groupSize || !mealType || !amount || !paymentMode || !name || !email || !phone) {
      return res.json({ success: false, error: "Missing required fields" });
    }

    const accommodation = await Accommodation.findById(accommodationId);
    if (!accommodation) {
      return res.json({ success: false, error: "Accommodation not found" });
    }

    const size = Number(groupSize);
    if (isNaN(size) || size < 1) {
      return res.json({ success: false, error: "Invalid group size" });
    }

    const date = new Date(stayDate);
    if (isNaN(date.getTime())) {
      return res.json({ success: false, error: "Invalid stay date" });
    }

    // Calculate expected amount
    const mealRate = mealType === "nonveg" ? accommodation.nonVegRate : accommodation.vegRate;
    const mealAmount = needStay ? mealRate * stayNight * size : mealRate * size;
    const stayAmount = needStay ? accommodation.pricePerNight * stayNight * size : 0;
    const expectedAmount = mealAmount + stayAmount;

    // Deposit logic
const depositAmount = paymentMode === 'cash' ? expectedAmount / 2 : expectedAmount; // The amount should match what we expect to charge now
const expectedChargeAmount = paymentMode === 'online' ? depositAmount : expectedAmount;

if (amount !== expectedChargeAmount) {
  return res.json({
    success: false,
    error: `Amount mismatch. Expected: ${expectedChargeAmount}, Received: ${amount}`
  });
}
const start = new Date(stayDate);
start.setUTCHours(0, 0, 0, 0);

const end = new Date(start);
end.setUTCDate(end.getUTCDate() + 1);


 

  const duplicate = await Booking.findOne({
      user: req.user._id,
      stayDate: { $gte: start, $lt: end },
      status: { $nin: ["cancelled", "completed"] }
    });



  if (duplicate) return res.status(400).json({ success: false, error: "You already have a booking for this date." });

   const alreadyBooked = await getBookedSeatsForDate(accommodationId, start);
    const seatsLeft = accommodation.maxMembers - alreadyBooked;
   
    if (size > seatsLeft) {
      return res.status(400).json({
        success: false,
        error: `Not enough capacity for ${start.toISOString().slice(0, 10)}. Available seats: ${seatsLeft}`
      });
    }

    // Create Razorpay Order (with booking data in notes)

    const bookingToken = uuidv4();
    await saveTempBooking(bookingToken, {
 
  accommodationId,
  name,
  email,
  phone,
  groupName,
  stayDate:start.toISOString(),
  groupSize,
  mealType,
  needStay,
  stayNight,
  paymentMode,
  fullAmount: expectedAmount,
  depositAmount,
});
const options = {
  amount: Math.round(depositAmount * 100),
  currency: "INR",
  receipt: `receipt_${Date.now()}`,
  payment_capture: 1,
  notes: {
    userId: req.user._id,
    bookingToken,
  },
};

    const order = await razorpay.orders.create(options);

    res.status(201).json({
      success: true,
      razorpayOrder: order,
      razorpayKey: process.env.RAZORPAY_KEY_ID,
      depositAmount,
      fullAmount: expectedAmount,
      message: "Order created. Complete payment to confirm booking."
    });
  } catch (error) {
    next(error);
  }
};

// Verify Payment Controller
export const verifyPayment = async (req, res) => {
  try {
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;

    // Verify signature
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    if (expectedSignature !== razorpay_signature) {
      return res.status(400).json({ success: false, error: "Invalid payment signature" });
    }

    // ✅ Signature valid → tell frontend to wait for webhook confirmation
    res.json({
      success: true,
      message: "Payment verified. Booking will be confirmed shortly once Razorpay notifies us."
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};




export const razorpayWebhook = async (req, res) => {
  try {
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
    const signature = req.headers["x-razorpay-signature"];

    // req.body is Buffer because express.raw({type: "application/json"})
    const bodyBuffer = req.body;
    const bodyString = bodyBuffer.toString("utf8");

    // Verify signature
    const expectedSignature = crypto
      .createHmac("sha256", webhookSecret)
      .update(bodyString)
      .digest("hex");

    if (signature !== expectedSignature) {
      console.warn("Invalid webhook signature");
      return res.status(400).send("Invalid signature");
    }

    const payload = JSON.parse(bodyString);
    const event = payload.event;

    // --------------------- PAYMENT EVENTS ---------------------
    if (event === "payment.captured" || event === "payment.failed") {
      const paymentEntity = payload.payload.payment.entity;
      const notes = paymentEntity.notes;

      // Prevent duplicate payment logs
      let paymentDoc = await Payment.findOne({ razorpayPaymentId: paymentEntity.id });
      if (!paymentDoc) {
        await Payment.create({
          user: notes.userId,
          razorpayOrderId: paymentEntity.order_id,
          razorpayPaymentId: paymentEntity.id,
          amount: paymentEntity.amount / 100,
          status: event === "payment.captured" ? "paid" : "failed",
        });
      }

      // Create booking only if payment success
if (event === "payment.captured") {
  const paymentEntity = payload.payload.payment.entity;
  const bookingToken = paymentEntity.notes.bookingToken;

  const bookingData = await getTempBooking(bookingToken);
  if (!bookingData) {
    console.warn("Booking token not found:", bookingToken);
    return res.status(400).send("Invalid booking token");
  }

  const booking = await Booking.create({
    user: notes.userId,
    name: bookingData.name,
    accommodation: bookingData.accommodationId,
    email: bookingData.email,
    phone: bookingData.phone,
    groupName: bookingData.groupName,
    stayDate: bookingData.stayDate,
    paymentMode: bookingData.paymentMode,
    amount: bookingData.fullAmount,
    depositAmount: bookingData.depositAmount,
    mealType: bookingData.mealType,
    needStay: bookingData.needStay,
    stayNight: bookingData.stayNight,
    groupSize: bookingData.groupSize,
    depositPaid: bookingData.paymentMode === "cash" ? true : false,
    remainingAmount: bookingData.paymentMode === "cash" ? bookingData.fullAmount - bookingData.depositAmount : 0,
    paymentStatus: bookingData.paymentMode === "cash" ? "pending" : "paid",
    status: "confirmed",
    razorpayOrderId: paymentEntity.order_id,
    transactionId: paymentEntity.id,
  });


  

  await deleteTempBooking(bookingToken);
await sendEmail({
  to: booking.email,
  subject: "Booking Confirmation ✅",
  html: `
  <!doctype html>
  <html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
  </head>
  <body style="margin:0;padding:0;background-color:#f4f6f8;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
      <tr>
        <td align="center" style="padding:24px 16px;">
          <table width="600" cellpadding="0" cellspacing="0" role="presentation" style="max-width:600px;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 6px 18px rgba(20,20,20,0.08);">
            
            <!-- content -->
            <tr>
              <td style="padding:28px 36px 18px 36px;font-family:Arial, Helvetica, sans-serif;color:#0f1724;">
                <h1 style="margin:0;font-size:20px;font-weight:700;color:#0b2545;">Booking Confirmation ✅</h1>
                <p style="margin:12px 0 20px;font-size:15px;line-height:1.5;color:#4b5563;">
                  Hi <strong>${booking.name}</strong>,<br><br>
                  Your booking <strong>#${booking._id}</strong> has been successfully confirmed.  
                  Here are your booking details:
                </p>

                <!-- details card -->
                <table cellpadding="0" cellspacing="0" role="presentation" style="width:100%;border:1px solid #e6e9ee;border-radius:8px;background:#fbfdff;">
                  <tr>
                    <td style="padding:14px 16px;font-size:14px;color:#334155;line-height:1.6;">
                      <strong>Group Name:</strong> ${booking.groupName}<br>
                      <strong>Accommodation:</strong> ${booking.accommodation}<br>
                      <strong>Stay Date:</strong> ${new Date(booking.stayDate).toLocaleDateString()}<br>
                      <strong>Stay Night(s):</strong> ${booking.stayNight}<br>
                      <strong>Meal Type:</strong> ${booking.mealType}<br>
                      <strong>Need Stay:</strong> ${booking.needStay ? "Yes" : "No"}<br>
                      <strong>Group Size:</strong> ${booking.groupSize}<br><br>

                      <strong>Payment Mode:</strong> ${booking.paymentMode}<br>
                      <strong>Total Amount:</strong> ₹${booking.amount}<br>
                      <strong>Deposit Amount:</strong> ₹${booking.depositAmount}<br>
                      <strong>Remaining Amount:</strong> ₹${booking.remainingAmount}<br>
                      <strong>Payment Status:</strong> ${booking.paymentStatus}<br><br>

                      <strong>Transaction ID:</strong> ${booking.transactionId}<br>
                      <strong>Razorpay Order ID:</strong> ${booking.razorpayOrderId}<br>
                    </td>
                  </tr>
                </table>

                <!-- CTA -->
                <p style="margin:18px 0 0;">
                  <a href="${booking.manageUrl ?? '#'}" style="display:inline-block;padding:10px 18px;border-radius:6px;background:#0b7bff;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;">
                    Manage Booking
                  </a>
                </p>
              </td>
            </tr>

            <!-- divider -->
            <tr>
              <td style="padding:0 36px;">
                <hr style="border:none;border-top:1px solid #eef2f7;margin:0;">
              </td>
            </tr>

            <!-- footer -->
            <tr>
              <td style="padding:18px 36px 28px;font-family:Arial, Helvetica, sans-serif;font-size:13px;color:#6b7280;">
                <p style="margin:0 0 8px;">If you have any questions, reply to this email or contact our support at <a href="mailto:support@your-domain.com" style="color:#0b7bff;text-decoration:none;">support@your-domain.com</a>.</p>
                <p style="margin:0;font-size:12px;color:#9aa3b2;">&copy; ${new Date().getFullYear()} Your Company Name. All rights reserved.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
  </html>
  `
});

} else {
        console.log("❌ Payment failed, booking not created.");
      }
    }

    // --------------------- REFUND EVENTS ---------------------
    if (event.startsWith("payment.refund")) {
      const refundEntity = payload.payload.refund?.entity || payload.payload.refund || {};
      const refundId = refundEntity.id;
      const paymentId = refundEntity.payment_id;
      const amount = (refundEntity.amount || 0) / 100;
      const status = refundEntity.status;

      let refundReq = await RefundRequest.findOne({ refundPaymentId: refundId });
      const paymentDocId = await Payment.findOne({ razorpayPaymentId: paymentId });
      if (!refundReq) {
        const paymentDoc = await Payment.findOne({ razorpayPaymentId: paymentId });
        if (paymentDoc) {
          refundReq = await RefundRequest.findOne({
            payment: paymentDoc._id,
            amount,
            status: { $in: ["initiated", "processing"] },
          });
        }
      }

      if (!refundReq) {
        console.warn("Unmatched refund webhook", refundId, paymentId);
        return res.status(200).send("ok");
      }

      let timelineEntry = {};

      if (status === "successful" || status === "paid") {
        refundReq.status = "refunded";
        refundReq.refundedAt = new Date();
        timelineEntry = { status: "refunded", message: "Refund successfully credited.", date: new Date() };

        await Booking.findByIdAndUpdate(refundReq.booking, {
          refundStatus: "refunded",
          refundId,
          refundedAt: new Date(),
        });
       await Payment.findByIdAndUpdate(paymentDocId._id,{refunded:true});
        const booking = await Booking.findById(refundReq.booking);
        await sendEmail({
          to: booking.email,
          subject: "Refund Successful ✅",
          text: `Hi ${booking.name}, your refund of ₹${amount} for booking ${booking._id} has been successfully credited to your bank account.`
        });

      } else if (status === "failed") {
        refundReq.status = "failed";
        refundReq.failedAt = new Date();
        timelineEntry = { status: "failed", message: "Refund failed at Razorpay.", date: new Date() };

        await Booking.findByIdAndUpdate(refundReq.booking, { refundStatus: "failed" });

      } else if (status === "processed" || status === "created" || status === "pending") {
        refundReq.status = "processing";
        refundReq.processedAt = new Date();
        timelineEntry = { status: "processing", message: "Refund request is being processed by Razorpay.", date: new Date() };

        await Booking.findByIdAndUpdate(refundReq.booking, { refundStatus: "processing" });
      }

      refundReq.refundPaymentId = refundId;
      if (timelineEntry.status) {
        refundReq.timeline.push(timelineEntry);
      }
      await refundReq.save();
    }

    res.status(200).send("ok");
  } catch (err) {
    console.error("razorpayWebhook error:", err);
    res.status(500).send("server error");
  }
};

export const completeOldBookings = async (req, res, next) => {
  try {
    const result = await autoCompleteBookings();
    res.status(200).json({
      success: true,
      message: "Bookings completed successfully",
      result,
    });
  } catch (error) {
    next(error);
  }
}



// Add this to your backend controllers
export const checkBookingConfirmation = async (req, res) => {
  try {
    const { orderId } = req.params;
    
    // Check if booking exists with this order ID
    const booking = await Booking.findOne({ razorpayOrderId: orderId });
    
    if (booking) {
      return res.json({ 
        success: true, 
        booking,
        message: "Booking confirmed" 
      });
    }
    
    // If not found yet
    return res.json({ 
      success: false, 
      message: "Booking not yet confirmed" 
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};


export const getMyBookings = catchAsyncErrors(async (req, res, next) => {
try {
  
    const userId = req.user._id;

  const bookings = await Booking.find({ user: userId }).sort({ stayDate: -1 });

  // if (!bookings || bookings.length === 0) {
  //   return next(new ErrorHandler('No bookings found for this user', 404));
  // }

  res.status(200).json({
    success: true,
    count: bookings.length,
    bookings,
  });
} catch (error) {
  console.log(error);
}
});



//   const session = await mongoose.startSession();
//   session.startTransaction();
  
//   try {
//     const { id } = req.params;
//     const userId = req.user._id; // Assuming authenticated user

//     // 1. Find the booking
//     const booking = await Booking.findById(id).session(session);
    
//     if (!booking) {
//       await session.abortTransaction();
//       session.endSession();
//       return res.status(404).json({ message: 'Booking not found' });
//     }

//     // 2. Check if user owns the booking
//     if (booking.user.toString() !== userId.toString()) {
//       await session.abortTransaction();
//       session.endSession();
//       return res.status(403).json({ message: 'Unauthorized to cancel this booking' });
//     }

//     // 3. Check booking status
//     if (booking.status === 'completed') {
//       await session.abortTransaction();
//       session.endSession();
//       return res.status(400).json({ message: 'Completed bookings cannot be canceled' });
//     }

//     if (booking.status === 'cancelled') {
//       await session.abortTransaction();
//       session.endSession();
//       return res.status(400).json({ message: 'Booking is already cancelled' });
//     }

//     // 4. Check 24-hour cancellation window
//     const now = new Date();
//     const bookingTime = new Date(booking.createdAt);
//     const hoursDiff = (now - bookingTime) / (1000 * 60 * 60);

//     if (hoursDiff > 24) {
//       await session.abortTransaction();
//       session.endSession();
//       return res.status(400).json({ message: 'Cancellation period expired (24 hours)' });
//     }

//     // 5. Update booking status
//     booking.status = 'cancelled';

 

//     await booking.save({ session });

//     // 6. Update accommodation bookedMembers
//     const accommodation = await Accommodation.findById(booking.accommodation).session(session);
    
//     if (accommodation) {
//       accommodation.bookedMembers = Math.max(0, accommodation.bookedMembers - booking.groupSize);
//       await accommodation.save({ session });
//     }

//     // 7. Commit transaction
//     await session.commitTransaction();
//     session.endSession();
    
//    if(booking.status==='cancelled')
//     {
//       return res.status(200).json({
//         success:true,
//         message:"your deposit amount has been refunded in working 3-4 business days."
//       })
//     }
    
//   } catch (error) {
//     // 8. Abort transaction on error
//     await session.abortTransaction();
//     session.endSession();
    
//     console.error('Cancel booking error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Internal server error',
//       error: error.message
//     });
//   }
// };

export const deleteBooking = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { id } = req.params;
    const userId = req.user._id;
    const role = req.user.role; // 'admin' or 'trekker'

    // 1️⃣ Find booking
    const booking = await Booking.findById(id).session(session);
    if (!booking) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ success: false, message: "Booking not found" });
    }

    // 2️⃣ Role-based authorization
    if (role === "trekker" && booking.user.toString() !== userId.toString()) {
      await session.abortTransaction();
      session.endSession();
      return res.status(403).json({ success: false, message: "Unauthorized to delete this booking" });
    }

    // 3️⃣ Check booking status
    if (!["cancelled", "completed"].includes(booking.status)) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ success: false, message: "Only cancelled or completed bookings can be deleted" });
    }

    // 4️⃣ Update deletion flags based on role
    if (role === "admin") {
      booking.deletedBy.admin = true;
    } else if (role === "trekker") {
      booking.deletedBy.user = true;
    }

    await booking.save({ session });

    // 5️⃣ Hard delete if both flags are true
    if (booking.deletedBy.admin && booking.deletedBy.user) {
      await Booking.deleteOne({ _id: booking._id }).session(session);
    }

    await session.commitTransaction();
    session.endSession();

    return res.status(200).json({
      success: true,
      message: booking.deletedBy.admin && booking.deletedBy.user
        ? "Booking permanently deleted"
        : "Booking marked as deleted"
    });

  } catch (error) {
    await session.abortTransaction();
    session.endSession();

    console.error("Delete booking error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message
    });
  }
};

export const cancelThenAutoRefund = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const bookingId = req.params.id;
    const userId = req.user._id;

    const booking = await Booking.findById(bookingId).session(session);
    if (!booking) {
      await session.abortTransaction(); session.endSession();
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    if (booking.user.toString() !== userId.toString()) {
      await session.abortTransaction(); session.endSession();
      return res.status(403).json({ success: false, message: 'Unauthorized to cancel this booking' });
    }

    if (booking.status === 'completed') {
      await session.abortTransaction(); session.endSession();
      return res.status(400).json({ success: false, message: 'Completed bookings cannot be canceled' });
    }
    if (booking.status === 'cancelled') {
      await session.abortTransaction(); session.endSession();
      return res.status(400).json({ success: false, message: 'Booking already cancelled' });
    }

    // 24-hour window check
    const now = new Date();
    const bookingTime = new Date(booking.createdAt);
    const hoursDiff = (now - bookingTime) / (1000 * 60 * 60);
    if (hoursDiff > 24) {
      await session.abortTransaction(); session.endSession();
      return res.status(400).json({ success: false, message: 'Cancellation period expired (24 hours)' });
    }

    // Prevent duplicate refund attempts
    const existing = await RefundRequest.findOne({
      booking: booking._id,
      status: { $in: ['initiated', 'processing'] }
    }).session(session);
    if (existing) {
      await session.abortTransaction(); session.endSession();
      return res.status(409).json({ success: false, message: 'Refund already in progress for this booking' });
    }

    // Compute refundable amount
    let refundableAmount = 0;
    if (booking.paymentMode === 'cash') {
      refundableAmount = booking.depositAmount || 0;
    } else {
      refundableAmount = booking.depositAmount ?? booking.amount ?? 0;
    }

    // Update booking & accommodation inside transaction
    booking.status = 'cancelled';
    booking.refundRequested = true;
    booking.refundAmount = refundableAmount;
    booking.refundStatus = booking.paymentMode === 'cash' ? 'initiated' : 'processing';
    await booking.save({ session });

    const accommodation = await Accommodation.findById(booking.accommodation).session(session);
    if (accommodation) {
      accommodation.bookedMembers = Math.max(0, accommodation.bookedMembers - (booking.groupSize || 1));
      await accommodation.save({ session });
    }

    // Link payment doc if present
    let paymentDoc = null;
    if (booking.razorpayOrderId) {
      paymentDoc = await Payment.findOne({ razorpayOrderId: booking.razorpayOrderId }).session(session);
    }
    if (!paymentDoc && booking.transactionId) {
      paymentDoc = await Payment.findOne({ razorpayPaymentId: booking.transactionId }).session(session);
    }

    // Create RefundRequest with timeline
    const [refundReq] = await RefundRequest.create([{
      booking: booking._id,
      user: userId,
      payment: paymentDoc ? paymentDoc._id : undefined,
      method: booking.paymentMode === 'cash' ? 'cash' : 'razorpay',
      amount: refundableAmount,
      reason: req.body.reason || 'User cancelled within refund window',
      status: booking.paymentMode === 'cash' ? 'initiated' : 'processing',
      initiatedAt: new Date(),
      timeline: [
        { status: "initiated", message: "Refund request initiated by user.", date: new Date() }
      ]
    }], { session });

    await sendEmail({
      to: booking.email,
      subject: "Refund Request Initiated 🔄",
      text: `Hi ${booking.name}, your refund request for booking on ${booking.stayDate} has been received.
You will receive confirmation once the refund is processed.`
    });

    await session.commitTransaction();
    session.endSession();

    // ONLINE: trigger Razorpay refund (outside transaction)
    try {
      const razorpayPaymentId = (paymentDoc && paymentDoc.razorpayPaymentId) || booking.transactionId;
      if (!razorpayPaymentId) {
        await RefundRequest.findByIdAndUpdate(refundReq._id, { 
          status: 'failed', 
          failedAt: new Date(),
          $push: { timeline: { status: "failed", message: "Missing original payment ID", date: new Date() } }
        });
        await Booking.findByIdAndUpdate(booking._id, { refundStatus: 'failed' });
        return res.status(400).json({ success: false, message: 'Original payment id missing; cannot auto-refund.' });
      }

      const amountPaise = Math.round(refundableAmount * 100);
      const refundResponse = await razorpay.payments.refund(razorpayPaymentId, { amount: amountPaise });

      const refundId = refundResponse && (refundResponse.id || (refundResponse.entity && refundResponse.entity.id));
      const gatewayStatus = refundResponse && (refundResponse.status || (refundResponse.entity && refundResponse.entity.status));

      const update = { refundPaymentId: refundId, processedAt: new Date() };
      let timelineEntry = {};

      if (gatewayStatus && (gatewayStatus === 'successful' || gatewayStatus === 'paid')) {
        update.status = 'refunded';
        update.refundedAt = new Date();
        timelineEntry = { status: "refunded", message: "Refund completed instantly by Razorpay.", date: new Date() };
        await Booking.findByIdAndUpdate(booking._id, { refundStatus: 'refunded', refundId, refundedAt: new Date() });
        await Payment.findByIdAndUpdate(paymentDoc._id,{refunded:true});
      } else {
        update.status = 'processing';
        timelineEntry = { status: "processing", message: "Refund request sent to Razorpay.", date: new Date() };
        await Booking.findByIdAndUpdate(booking._id, { refundStatus: 'processing', refundId });
      }

      update.$push = { timeline: timelineEntry };
      await RefundRequest.findByIdAndUpdate(refundReq._id, update, { new: true });

      return res.status(200).json({
        success: true,
        message: 'Booking cancelled and refund triggered; final confirmation will come via webhook.',
        refundResponse
      });

    } catch (gatewayErr) {
      console.error('Gateway refund error', gatewayErr);
      await RefundRequest.findByIdAndUpdate(refundReq._id, { 
        status: 'failed', 
        failedAt: new Date(),
        $push: { timeline: { status: "failed", message: `Gateway error: ${gatewayErr.message}`, date: new Date() } }
      });
      await Booking.findByIdAndUpdate(booking._id, { refundStatus: 'failed' });
      await sendEmail({
        to: booking.email,
        subject: "Refund Failed",
        text: `Booking cancelled but refund attempt failed. Admin will review.`
      });
      return res.status(500).json({ success: false, message: 'Booking cancelled but refund attempt failed. Admin will review.', error: gatewayErr.message });
    }

  } catch (err) {
    try { await session.abortTransaction(); } catch (e) {}
    session.endSession();
    console.error('cancelThenAutoRefund error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
  }
};



export const adminProcessRefund = async (req, res) => {

  try {
    const user = req.user;
    if (!user?.isAdmin) return res.status(403).json({ success: false, message: 'Unauthorized' });

    const { refundId } = req.params;
    const { action, adminNotes } = req.body;

    const refundReq = await RefundRequest.findById(refundId).populate('payment booking');
    if (!refundReq) return res.status(404).json({ success: false, message: 'Refund request not found' });
    // Cash refund: mark refunded
    if (refundReq.method === 'cash') {
      refundReq.status = 'refunded';
      refundReq.adminNotes = (refundReq.adminNotes || '') + '\n' + (adminNotes || `Cash refunded by admin ${user._id}`);
      refundReq.processedAt = new Date();
      await refundReq.save();

      await Booking.findByIdAndUpdate(refundReq.booking, {
        refundStatus: 'refunded',
        refundId: `cash_${refundReq._id}`,
        refundedAt: new Date()
      });

      return res.json({ success: true, message: 'Cash refund marked as completed', refundReq });
    }

    // For razorpay refunds: allow admin retry
    if (refundReq.method === 'razorpay') {
      if (refundReq.status === 'processing') {
        return res.status(400).json({ success: false, message: 'Refund already processing' });
      }

      // find payment id
      let razorpayPaymentId = null;
      if (refundReq.payment && refundReq.payment.razorpayPaymentId) {
        razorpayPaymentId = refundReq.payment.razorpayPaymentId;
      } else {
        const booking = await Booking.findById(refundReq.booking);
        razorpayPaymentId = booking?.transactionId;
      }

      if (!razorpayPaymentId) {
        refundReq.status = 'failed';
        refundReq.adminNotes = (refundReq.adminNotes || '') + '\n' + 'Cannot find original payment id for gateway refund';
        await refundReq.save();
        return res.status(400).json({ success: false, message: 'Original payment id missing' });
      }

      try {
        refundReq.status = 'processing';
        await refundReq.save();

        const amountPaise = Math.round(refundReq.amount * 100);
        const refundResponse = await razorpay.payments.refund(razorpayPaymentId, { amount: amountPaise });

        const refundGatewayId = refundResponse && (refundResponse.id || (refundResponse.entity && refundResponse.entity.id));
        const gatewayStatus = refundResponse && (refundResponse.status || (refundResponse.entity && refundResponse.entity.status));

        refundReq.refundPaymentId = refundGatewayId;
        refundReq.processedAt = new Date();
        refundReq.adminNotes = (refundReq.adminNotes || '') + '\n' + (adminNotes || `Refund retried by admin ${user._id}`);
        refundReq.status = (gatewayStatus && (gatewayStatus === 'processed' || gatewayStatus === 'successful' || gatewayStatus === 'paid')) ? 'refunded' : 'processing';
        await refundReq.save();

        if (refundReq.status === 'refunded') {
          await Booking.findByIdAndUpdate(refundReq.booking, { refundStatus: 'refunded', refundId: refundGatewayId, refundedAt: new Date() });
        }

        return res.json({ success: true, message: 'Gateway refund triggered', refundResponse });
      } catch (err) {
        console.error('admin retry refund error', err);
        refundReq.status = 'failed';
        refundReq.adminNotes = (refundReq.adminNotes || '') + '\n' + `Gateway retry error: ${err.message}`;
        await refundReq.save();
        await Booking.findByIdAndUpdate(refundReq.booking, { refundStatus: 'failed' });
        return res.status(500).json({ success: false, message: 'Gateway refund retry failed', error: err.message });
      }
    }

    return res.status(400).json({ success: false, message: 'Unsupported refund method' });
  } catch (err) {
    console.error('adminProcessRefund error', err);
    return res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
  }
};



export const getRefundStatus = async (req, res) => {
  try {
    const bookingId = req.params.id;
    const userId = req.user._id;

    const booking = await Booking.findById(bookingId);
    if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });
    if (booking.user.toString() !== userId.toString()) return res.status(403).json({ success: false, message: 'Unauthorized' });

    const refundReq = await RefundRequest.findOne({ booking: booking._id }).sort({ createdAt: -1 });

    return res.json({
      success: true,
      booking: {
        id: booking._id,
        status: booking.status,
        refundStatus: booking.refundStatus,
        refundAmount: booking.refundAmount,
        refundId: booking.refundId || null
      },
      refundRequest: refundReq || null
    });
  } catch (err) {
    console.error('getRefundStatus error', err);
    return res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
  }
};
