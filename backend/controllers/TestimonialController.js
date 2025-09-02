import Testimonial from "../models/Testimonial.model.js";
import Booking from "../models/Booking.model.js"
import { sendEmail } from "../utils/emailService.js";
// Add Testimonial (just use stayDate + user)
export const addTestimonial = async (req, res) => {
  try {
    const { stayDate, rating, comment } = req.body;

    if (!stayDate || !rating || !comment) {
      return res.status(400).json({ success: false, error: "Stay date, rating and comment are required" });
    }

    // 1️⃣ Find the booking for this user & stayDate
    const booking = await Booking.findOne({
      user: req.user._id,
      stayDate: new Date(stayDate),
      status: "completed", // only after stay completed
    });

    if (!booking) {
      return res.status(404).json({
        success: false,
      error: "No completed booking found for this stay date",
      });
    }

    // 2️⃣ Prevent duplicate testimonial
    const existing = await Testimonial.findOne({
      booking: booking._id,
      user: req.user._id,
    });

    if (existing) {
      return res.status(400).json({
        success: false,
        error: "You already left a testimonial for this booking",
      });
    }

    // 3️⃣ Create testimonial
    const testimonial = await Testimonial.create({
      booking: booking._id,
      user: req.user._id,
      rating,
      comment,
    });

   await sendEmail({
  to: booking.email,
  subject: "Thank You for Your Feedback 🙏",
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
            <table width="600" cellpadding="0" cellspacing="0" role="presentation" 
                   style="max-width:600px;background:#ffffff;border-radius:8px;
                   overflow:hidden;box-shadow:0 6px 18px rgba(20,20,20,0.08);">

              <tr>
                <td style="padding:32px 36px;font-family:Arial, Helvetica, sans-serif;color:#0f1724;text-align:center;">
                  <h1 style="margin:0;font-size:22px;font-weight:700;color:#0b2545;">
                    Thank You for Your Feedback 🙏
                  </h1>
                  <p style="margin:20px 0 0;font-size:15px;line-height:1.6;color:#4b5563;">
                    Hello <strong>${booking.name}</strong>,<br><br>
                    Thank you for sharing your feedback on your stay from 
                    <strong>${new Date("Sat Sep 27 2025 00:00:00 GMT+0000").toDateString()}</strong>.  
                    We truly appreciate your input and it helps us improve our services.
                  </p>
                  <p style="margin:20px 0 0;font-size:15px;line-height:1.6;color:#4b5563;">
                    We look forward to welcoming you again soon!
                  </p>
                  <p style="margin:30px 0 0;font-size:14px;color:#0f1724;font-weight:600;">
                    Regards,<br>Suraj Kadam
                  </p>
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

    res.status(201).json({ success: true, testimonial,message: "Testimonial added successfully" });
  } catch (error) {
   console.log(error);
   res.status(500).json({ success: false, error: "Server Error" });
  }
};

export const getMyReview = async (req, res) => {
  try {
    const userId = req.user?._id; // Auth middleware should attach user

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized. Please log in again.",
      });
    }

    // Pagination
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const skip = (page - 1) * limit;

    // Fetch reviews
    const [reviews, total] = await Promise.all([
      Testimonial.find({ user: userId })
        .populate("booking", "stayDate groupSize status") // only safe fields
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Testimonial.countDocuments({ user: userId }),
    ]);

    return res.status(200).json({
      success: true,
      data: reviews,
      meta: {
        total,
        page,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error("getMyReview error:", err);
    return res.status(500).json({
      success: false,
      message: "Server error while fetching your reviews",
    });
  }
};

export const deleteReview = async (req, res) => {
  try {
    const { reviewId } = req.params;
    const userId = req.user?._id;
    const userRole = req.user?.role;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized. Please log in again.",
      });
    }

    const review = await Testimonial.findById(reviewId);
    if (!review) {
      return res.status(404).json({
        success: false,
        message: "Review not found",
      });
    }

    // Only owner or admin can delete
    if (review.user.toString() !== userId.toString() && userRole !== "admin") {
      return res.status(403).json({
        success: false,
        message: "You are not allowed to delete this review",
      });
    }

    await review.deleteOne(); // ✅ Hard delete

    return res.status(200).json({
      success: true,
      message: "Review deleted successfully",
    });
  } catch (err) {
    console.error("deleteReview error:", err);
    return res.status(500).json({
      success: false,
      message: "Server error while deleting review",
    });
  }
};




export const getAllTestimonials = async (req, res) => {
  try {
    const { page = 1, limit = 10, keyword, status } = req.query;
   

    const pageNumber = Number(page) || 1;
    const pageSize = Number(limit) || 10;

    // Build filter object
    const filter = {};

    // Keyword search (on name or comment)
    if (keyword) {
      filter.$or = [
        { name: { $regex: keyword, $options: "i" } },
        { comment: { $regex: keyword, $options: "i" } },
      ];
    }

    // Status filter (approved / pending / rejected)
 if (status && status.toLowerCase() !== "all") {
  filter.status = status;
}


    // Count total documents for pagination
    const total = await Testimonial.countDocuments(filter);

    // Fetch testimonials with pagination
    const testimonials = await Testimonial.find(filter)
      .populate("user", "name email")
      .populate("booking", "stayDate groupSize")
      .sort({ createdAt: -1 }) // latest first
      .skip((pageNumber - 1) * pageSize)
      .limit(pageSize)
      .lean();


    res.status(200).json({
      success: true,
      count: testimonials.length,
      totalPages: Math.ceil(total / pageSize),
      currentPage: pageNumber,
      totalRecords: total,
      testimonials,
    });
  } catch (error) {
    console.error("Error fetching testimonials:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Something went wrong while fetching testimonials",
    });
  }
};


export const updateReviewStatus = async (req, res) => {
  try {
    const { reviewId } = req.params;
    const { status } = req.body; // expected: "approved" | "rejected"



    // Only allow valid enum values
    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid status. Must be 'approved' or 'rejected'.",
      });
    }

    const review = await Testimonial.findById(reviewId);
    if (!review) {
      return res.status(404).json({
        success: false,
        message: "Review not found",
      });
    }

    review.status = status;
    await review.save();

    return res.status(200).json({
      success: true,
      message: `Review ${status} successfully`,
      review,
    });
  } catch (err) {
    console.error("updateReviewStatus error:", err);
    return res.status(500).json({
      success: false,
      message: "Server error while updating review status",
    });
  }
};
