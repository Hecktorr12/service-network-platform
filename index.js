import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import flash from "connect-flash";
import multer from "multer";
import fs from "fs";

const uploadDir = "uploads/";
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}


const app = express();
env.config();
const saltRounds = 10;

// PostgreSQL Connection
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "uploads/"); // Ensure the 'uploads' folder exists
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    }
});

const upload = multer({ storage: storage });

app.use(express.json()); // Parses JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parses URL-encoded request bodies





app.use(express.static("public"));
app.use('/public/uploads', express.static('public/uploads'));


app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: { maxAge: 1 * 60 * 60 * 1000 }
    })
);

app.use(flash());

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
    res.render('index.ejs');
});

app.get("/signup-professional", (req, res) => {
    res.render("signup-professional.ejs", { messages: req.flash() });
});

app.get("/signup-company", (req, res) => {
    res.render("signup-company.ejs", { messages: req.flash() });
});

app.get('/login', (req, res) => {
    res.render('login.ejs', { messages: req.flash() });
});
app.get('/admin-home', async(req, res) =>{
    try {
        // Fetch unverified companies
        const companies = await db.query(
            "SELECT * FROM users WHERE is_verified = false AND role = 'company'"
        );

        // Fetch unverified professionals
        const professionals = await db.query(
            "SELECT * FROM users WHERE is_verified = false AND role = 'professional'"
        ); 

        res.render("admin-home", {
            companies: companies.rows,
            professionals: professionals.rows,
            messages: req.flash()
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
})
app.get('/company-home', async (req, res) => {
    try {
        const companyId = req.session.user.id; // Assuming `req.user` contains the logged-in user's info

        // Query to get total jobs posted
        const totalJobsQuery = await db.query(
            'SELECT COUNT(*) AS total_jobs FROM jobs WHERE company_id = $1', 
            [companyId]
        );

        // Query to get completed jobs
        const completedJobsQuery = await db.query(
            "SELECT COUNT(*) AS completed_jobs FROM jobs WHERE company_id = $1 AND status = 'completed'", 
            [companyId]
        );

        // Query to get pending payments
        const pendingPaymentsQuery = await db.query(
            'SELECT COALESCE(SUM(pay), 0) AS pending_payments FROM payment_requests WHERE company_id = $1 AND company_payment_status = FALSE', 
            [companyId]
        );

        // Query to get company name
        const companyNameQuery = await db.query(
            'SELECT full_name FROM users WHERE id = $1', 
            [companyId]
        );

        // Extract values
        const totalJobs = totalJobsQuery.rows[0].total_jobs || 0;
        const completedJobs = completedJobsQuery.rows[0].completed_jobs || 0;
        const pendingPayments = pendingPaymentsQuery.rows[0].pending_payments || 0;
        const companyName = companyNameQuery.rows[0]?.full_name || 'Company';

        // Render EJS file with data
        res.render('company-home', {
            companyName,
            totalJobs,
            completedJobs,
            pendingPayments
        });
    } catch (error) {
        console.error('Error fetching company dashboard data:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get("/company-jobs", async (req, res) => {
    try {
        const userId = req.session.user.id; // Assuming session stores logged-in user
        if (!userId) {
            req.flash("error", "You need to log in first.");
            return res.redirect("/login");
        }

        // Fetch jobs posted by the logged-in company
        const jobsResult = await db.query("SELECT * FROM jobs WHERE company_id = $1", [userId]);
        const jobs = jobsResult.rows;

        // Fetch stages for each job
        for (let job of jobs) {
            const stagesResult = await db.query("SELECT * FROM job_stages WHERE job_id = $1", [job.id]);
            job.stages = stagesResult.rows;
        }
        
        res.render("company-jobs", { jobs , messages: req.flash()});
    } catch (error) {
        console.error("Error fetching jobs:", error);
        req.flash("error", "Failed to load jobs.");
        res.redirect("/dashboard");
    }
});

app.get("/company-pending-payments",async (req,res)=>{
    try {
        const companyId = req.session.user.id; // Assuming the logged-in user is stored in req.user

        // Fetch pending payment requests for this company
        const result = await db.query(
            `SELECT pr.id, pr.professional_id, pr.job_title, pr.pay, pr.bank_name, 
             pr.account_number, pr.account_name, pr.company_payment_status, u.full_name AS professional_name
             FROM payment_requests pr
             JOIN users u ON pr.professional_id = u.id
             WHERE pr.company_id = $1`,
            [companyId]
        );

        res.render("company-pending-payments", { payments: result.rows });
    } catch (error) {
        console.error("Error fetching payment requests:", error);
        res.status(500).send("Internal Server Error");
    }
})

app.get("/professional-available-jobs", async (req, res) => {
    try {
        if (!req.session.user) {
            return res.redirect("/login"); // Redirect if not logged in
        }

        const professionalId = req.session.user.id; // Get logged-in professional's ID

        // Fetch professional details from the database
        const professionalQuery = "SELECT * FROM users WHERE id = $1 AND role = 'professional';";
        const professionalResult = await db.query(professionalQuery, [professionalId]);

        if (professionalResult.rows.length === 0) {
            return res.status(403).send("Unauthorized access");
        }

        const professional = professionalResult.rows[0]; // Store full professional data

        const jobQuery = `
            SELECT jobs.id, jobs.title, jobs.description, jobs.total_work_time, jobs.pay, jobs.status, users.full_name AS company_name
            FROM jobs
            JOIN users ON jobs.company_id = users.id
            WHERE users.role = 'company';
        `;
        const jobsResult = await db.query(jobQuery);
        const jobs = jobsResult.rows;

        // Fetch job stages for each job
        for (let job of jobs) {
            const stageQuery = "SELECT stage_name, hours_required FROM job_stages WHERE job_id = $1;";
            const stageResult = await db.query(stageQuery, [job.id]);
            job.stages = stageResult.rows; // Attach stages to the job object
        }

        // Pass the full professional object to the template
        res.render("professional-available-jobs", { jobs, professional, messages: req.flash() });
    } catch (error) {
        console.error("Error fetching jobs:", error);
        res.status(500).send("Internal Server Error");
    }
});



app.get("/professional-home", async (req, res) => {
    try {
        const professionalId = req.session.user.id; // Get logged-in user's ID

        // Fetch professional's name
        const userQuery = await db.query(
            "SELECT full_name, total_hours_worked FROM users WHERE id = $1",
            [professionalId]
        );
        const professionalName = userQuery.rows[0].full_name;
        const totalHoursWorked = userQuery.rows[0].total_hours_worked;

        // Fetch total jobs taken (jobs where status is 'accepted' in job_applications)
        const jobsTakenQuery = await db.query(
            "SELECT COUNT(*) FROM job_applications WHERE professional_id = $1 AND status = 'accepted'",
            [professionalId]
        );
        const totalJobsTaken = jobsTakenQuery.rows[0].count;

        // Fetch completed jobs (jobs where status is 'fully completed' in enrolled_jobs)
        const completedJobsQuery = await db.query(
            "SELECT COUNT(*) FROM enrolled_jobs WHERE professional_id = $1 AND status = 'fully completed'",
            [professionalId]
        );
        const completedJobs = completedJobsQuery.rows[0].count;

        // Fetch pending payments (sum of pay column in payment_requests where professional_receipt_status = false)
        const pendingPaymentsQuery = await db.query(
            "SELECT COALESCE(SUM(pay), 0) AS pending_payments FROM payment_requests WHERE professional_id = $1 AND professional_receipt_status = false",
            [professionalId]
        );
        const pendingPayments = pendingPaymentsQuery.rows[0].pending_payments;

        // Render the EJS page with fetched data
        res.render("professional-home", {
            professionalName,
            totalJobsTaken,
            completedJobs,
            pendingPayments,
            totalHoursWorked,
        });
    } catch (error) {
        console.error("Error fetching professional dashboard data:", error);
        res.status(500).send("Server Error");
    }
});



app.get("/professional-enrolled-jobs", async (req, res) => {
    try {
        const professionalId = req.session.user.id; // Assuming the professional is logged in and stored in session

        if (!professionalId) {
            return res.redirect("/login"); // Redirect to login if not authenticated
        }

        // Query to fetch enrolled jobs for the logged-in professional
        const jobQuery = `
            SELECT 
                jobs.id AS job_id, jobs.title, jobs.description, jobs.total_work_time, jobs.pay, jobs.status AS job_status,
                users.full_name AS company_name, users.email AS company_email, users.phone_number AS company_phone,
                enrolled_jobs.status AS enrollment_status
            FROM enrolled_jobs
            JOIN jobs ON enrolled_jobs.job_id = jobs.id
            JOIN users ON jobs.company_id = users.id
            WHERE enrolled_jobs.professional_id = $1
        `;

        const { rows: enrolledJobs } = await db.query(jobQuery, [professionalId]);

        // Fetch job stages for each job
        for (let job of enrolledJobs) {
            const stageQuery = `
                SELECT stage_name, hours_required
                FROM job_stages
                WHERE job_id = $1
            `;

            const { rows: stages } = await db.query(stageQuery, [job.job_id]);

            job.stages = stages; // Attach stages to each job
        }

        res.render("professional-enrolled-jobs", { enrolledJobs });

    } catch (error) {
        console.error("Error fetching enrolled jobs:", error);
        res.status(500).send("Server error");
    }
});


/* app.get("/professional-payment-requests", async(req, res) => {
    try {
        const professionalId = req.session.user.id;

        // Fetch completed jobs awaiting payment with payment request info
        const query = `
            SELECT ej.id AS enrolled_job_id, j.title AS job_title, j.pay, 
            u.full_name AS company_name, u.email AS company_contact, u.phone_number AS company_number,
            pr.id AS payment_request_id, pr.professional_receipt_status
            FROM enrolled_jobs ej
            JOIN jobs j ON ej.job_id = j.id
            JOIN users u ON j.company_id = u.id
            LEFT JOIN payment_requests pr ON ej.id = pr.enrolled_job_id
            WHERE ej.professional_id = $1 AND ej.status = 'completed (awaiting payment)';
        `;

        const { rows: jobs } = await db.query(query, [professionalId]);
        res.render('professional-payment-requests', { jobs });
    } catch (error) {
        console.error('Error fetching payment requests:', error);
        res.status(500).send('Server error');
    }
}); */
app.get("/professional-payment-requests", async(req, res) => {
    try {
        const professionalId = req.session.user.id;
        
        // First, get the professional's total hours worked
        const hoursQuery = `
            SELECT total_hours_worked 
            FROM users 
            WHERE id = $1
        `;
        const hoursResult = await db.query(hoursQuery, [professionalId]);
        const totalHoursWorked = hoursResult.rows.length > 0 ? hoursResult.rows[0].total_hours_worked : 0;
        
        // Fetch completed jobs awaiting payment with payment request info
        const jobsQuery = `
            SELECT ej.id AS enrolled_job_id, j.title AS job_title, j.pay, 
            u.full_name AS company_name, u.email AS company_contact, u.phone_number AS company_number,
            pr.id AS payment_request_id, pr.professional_receipt_status
            FROM enrolled_jobs ej
            JOIN jobs j ON ej.job_id = j.id
            JOIN users u ON j.company_id = u.id
            LEFT JOIN payment_requests pr ON ej.id = pr.enrolled_job_id
            WHERE ej.professional_id = $1 AND ej.status = 'completed (awaiting payment)'
        `;
        
        const { rows: jobs } = await db.query(jobsQuery, [professionalId]);
        
        // Pass both jobs and the hours to the template
        res.render('professional-payment-requests', { 
            jobs, 
            totalHoursWorked,
            canRequestPayment: totalHoursWorked >= 200
        });
    } catch (error) {
        console.error('Error fetching payment requests:', error);
        res.status(500).send('Server error');
    }
});

app.get("/professional-job-history",async (req, res) => {
    try {
        const professionalId = req.session.user.id; // Get the logged-in professional's ID

        // Fetch completed jobs assigned to the logged-in professional
        const completedJobsQuery = `
            SELECT jobs.title, jobs.description, users.full_name AS company_name 
            FROM jobs
            JOIN enrolled_jobs ON jobs.id = enrolled_jobs.job_id
            JOIN users ON jobs.company_id = users.id
            WHERE enrolled_jobs.professional_id = $1 AND jobs.status = 'completed';
        `;

        const { rows: completedJobs } = await db.query(completedJobsQuery, [professionalId]);

        res.render("professional-job-history", { completedJobs, messages: {} });

    } catch (err) {
        console.error("Error fetching completed jobs:", err);
        res.render("professional-job-history", { completedJobs: [], messages: { error: ["Failed to load jobs."] } });
    }
});

app.get('/company-job-history', async (req, res) => {
    try {
        const companyId = req.session.user.id; // Ensure user is authenticated

        if (!companyId) {
            req.flash('error', 'Unauthorized access');
            return res.redirect('/login');
        }

        // Fetch completed jobs posted by this company
        const completedJobsQuery = `
            SELECT j.id, j.title, j.description, u.full_name AS professional
            FROM jobs j
            JOIN enrolled_jobs ej ON j.id = ej.job_id
            JOIN users u ON ej.professional_id = u.id
            WHERE j.company_id = $1 AND j.status = 'completed'
        `;

        const { rows: completedJobs } = await db.query(completedJobsQuery, [companyId]);

        res.render('company-job-history', { completedJobs });
    } catch (error) {
        console.error("Error fetching completed jobs:", error);
        req.flash('error', 'Failed to load jobs');
        res.render('company-job-history', { completedJobs: [] });
    }
});

// ======================
//  SIGNUP - PROFESSIONAL
// ======================
app.post('/signup-professional', upload.single("verification_document"),async (req, res) => {
    console.log(req.body); // Debugging: See if password is present

    const { full_name, email, password, phone_number, location, field_of_expertise, years_of_experience, short_bio } = req.body;
    const verification_document = req.file ? req.file.filename : null;

    try {
        if (!password) {
            req.flash("error", "Password is required.");
            return res.redirect("/signup-professional");
        }

        // Trim password to remove spaces
        const hashedPassword = await bcrypt.hash(password.trim(), saltRounds);

        // Check if email already exists
        const userExists = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userExists.rows.length > 0) {
            req.flash("error", "Email already registered.");
            return res.redirect("/signup-professional");
        }

        // Insert user into database
        await db.query(
            "INSERT INTO users (full_name, email, password_hash, phone_number, location, field_of_expertise, years_of_experience, short_bio, verification_document, role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'professional')",
            [full_name, email, hashedPassword, phone_number, location, field_of_expertise, years_of_experience, short_bio, verification_document]
        );

        req.flash("success", "Signup successful! Please login.");
        res.redirect("/login");

    } catch (error) {
        console.error("Error during signup:", error);
        req.flash("error", "An error occurred. Please try again.");
        res.redirect("/signup-professional");
    }
});


// ======================
//  SIGNUP - COMPANY
// ======================
app.post('/signup-company', upload.single("verification_document"), async (req, res) => {
    console.log(req.body); // Debugging: Check request data

    const { full_name, email, password, location, phone_number, industry_type, company_description, company_website } = req.body;
    const verification_document = req.file ? req.file.filename : null;

    try {
        if (!password) {
            req.flash("error", "Password is required.");
            return res.redirect("/signup-company");
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password.trim(), saltRounds);

        // Check if email already exists
        const userExists = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userExists.rows.length > 0) {
            req.flash("error", "Email already registered.");
            return res.redirect("/signup-company");
        }

        // Insert company into the database
        await db.query(
            `INSERT INTO users (full_name, email, password_hash, location, phone_number, industry_type, company_description, company_website, verification_document, role) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'company')`,
            [full_name, email, hashedPassword, location, phone_number, industry_type, company_description, company_website, verification_document]
        );

        req.flash("success", "Signup successful! Your account is under review.");
        res.redirect("/login");

        

    } catch (error) {
        console.error("Error during company signup:", error);
        req.flash("error", "An error occurred. Please try again.");
        res.redirect("/signup-company");
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if user exists
        const userResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

        if (userResult.rows.length === 0) {
            req.flash("error", "Invalid email or password.");
            return res.redirect("/login");
        }

        const user = userResult.rows[0];

        // Check if the user is verified
        if (!user.is_verified) {
            req.flash("error", "Your account has not been verified.");
            return res.redirect("/login");
        }

        // Compare password hash
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            req.flash("error", "Invalid email or password.");
            return res.redirect("/login");
        }

        // Store user details in session
        req.session.user = {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
            role: user.role
        };

        // Redirect based on role
        if (user.role === 'admin') {
            res.redirect('/admin-home');
        } else if (user.role === 'company') {
            res.redirect('/company-home');
        } else if (user.role === 'professional') {
            res.redirect('/professional-home');
        } else {
            req.flash("error", "Unauthorized access.");
            res.redirect("/login");
        }

    } catch (error) {
        console.error("Login error:", error);
        req.flash("error", "An error occurred. Please try again.");
        res.redirect("/login");
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.redirect("/"); // Redirect to home if there's an error
        }
        res.redirect('/login'); // Redirect to login after logout
    });
});

app.post("/admin/approve", async (req, res) => {
    const { user_id } = req.body;
    await db.query("UPDATE users SET is_verified = true WHERE id = $1", [user_id]);
    res.redirect("/admin-home");
});

app.post("/admin/reject", async (req, res) => {
    const { user_id } = req.body;
    await db.query("DELETE FROM users WHERE id = $1", [user_id]);
    res.redirect("/admin-home");
});

app.post("/company/jobs/create", async (req, res) => {
    try {
        const userId = req.session.user.id;
        if (!userId) {
            req.flash("error", "You need to log in first.");
            return res.redirect("/login");
        }

        const { title, description, total_hours, pay, stages, stage_times } = req.body;

        // Insert job into the jobs table
        const jobResult = await db.query(
            "INSERT INTO jobs (company_id, title, description, total_work_time, pay, status) VALUES ($1, $2, $3, $4, $5, 'not started') RETURNING id",
            [userId, title, description, total_hours, pay]
        );

        const jobId = jobResult.rows[0].id;

        // Insert stages into job_stages table
        if (stages && stage_times) {
            for (let i = 0; i < stages.length; i++) {
                await db.query(
                    "INSERT INTO job_stages (job_id, stage_name, hours_required) VALUES ($1, $2, $3)",
                    [jobId, stages[i], stage_times[i]]
                );
            }
        }

        req.flash("success", "Job posted successfully.");
        res.redirect("/company-jobs");
    } catch (error) {
        console.error("Error creating job:", error);
        req.flash("error", "Failed to create job.");
        res.redirect("/company-jobs");
    }
});

/* app.post("/company/jobs/:jobId/accept/:applicantId", async (req, res) => {
    try {
        const { jobId, applicantId } = req.params;

        // Update job status
        await db.query("UPDATE jobs SET status = 'In Progress' WHERE id = $1", [jobId]);

        // Update application status
        await db.query("UPDATE job_applications SET status = 'Accepted' WHERE job_id = $1 AND applicant_id = $2", [jobId, applicantId]);

        req.flash("success", "Applicant accepted. Job is now in progress.");
        res.redirect("/company-jobs");
    } catch (error) {
        console.error("Error accepting applicant:", error);
        req.flash("error", "Failed to accept applicant.");
        res.redirect("/company-jobs");
    }
}); */

app.post("/company/jobs/:jobId/delete", async (req, res) => {
    try {
        const { jobId } = req.params;

        // Delete job stages first (to avoid foreign key constraint)
        await db.query("DELETE FROM job_stages WHERE job_id = $1", [jobId]);

        // Delete job
        await db.query("DELETE FROM jobs WHERE id = $1", [jobId]);

        req.flash("success", "Job deleted successfully.");
        res.redirect("/company-jobs");
    } catch (error) {
        console.error("Error deleting job:", error);
        req.flash("error", "Failed to delete job.");
        res.redirect("/company-jobs");
    }
});
app.post("/apply-job", async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ message: "Unauthorized: Please log in first" });
        }

        const { job_id, professional_id } = req.body;

        // Check if the professional has already applied
        const checkQuery = "SELECT * FROM job_applications WHERE job_id = $1 AND professional_id = $2;";
        const checkResult = await db.query(checkQuery, [job_id, professional_id]);

        if (checkResult.rows.length > 0) {
            req.flash("error", "You have already applied for this job.");
        }

        // Insert application into the database
        else{
            const insertQuery = "INSERT INTO job_applications (job_id, professional_id) VALUES ($1, $2);";
            await db.query(insertQuery, [job_id, professional_id]);
            req.flash("success", "You have applied for the job.");
        };

        res.redirect("/professional-available-jobs"); // Redirect after applying
    } catch (error) {
        console.error("Error applying for job:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/company/jobs/:jobId/applicants", async (req, res) => {
    try {
        const { jobId } = req.params;

        const applicantsResult = await db.query(
            `SELECT u.id, u.full_name 
             FROM job_applications ja 
             JOIN users u ON ja.professional_id = u.id 
             WHERE ja.job_id = $1 AND ja.status = 'pending'`,
            [jobId]
        );

        res.json(applicantsResult.rows);
    } catch (error) {
        console.error("Error fetching applicants:", error);
        res.status(500).json({ error: "Failed to load applicants" });
    }
});
app.post("/company/jobs/:jobId/accept/:applicantId", async (req, res) => {
    try {
        const { jobId, applicantId } = req.params;

        // Update job application status
        await db.query(
            `UPDATE job_applications SET status = 'accepted' 
             WHERE job_id = $1 AND professional_id = $2`,
            [jobId, applicantId]
        );

        // Enroll the applicant in the job
        await db.query(
            `INSERT INTO enrolled_jobs (job_id, professional_id, status) 
             VALUES ($1, $2, 'in progress')`,
            [jobId, applicantId]
        );
        await db.query(
            `UPDATE jobs SET status = 'in progress' 
             WHERE id = $1 `,
            [jobId]
        );

        res.json({ success: true });
    } catch (error) {
        console.error("Error accepting applicant:", error);
        res.status(500).json({ success: false, error: "Failed to accept applicant" });
    }
});

app.post('/update-job-status', async (req, res) => {
    try {
        const { jobId, newStatus } = req.body;
        const professionalId = req.session.user.id;

        if (!professionalId) {
            return res.status(401).json({ success: false, message: "Unauthorized" });
        }

        // Ensure the status is only updated to valid states
        const validStatuses = ["in progress", "completed (awaiting payment)"];
        if (!validStatuses.includes(newStatus.toLowerCase())) {
            return res.status(400).json({ success: false, message: "Invalid status value" });
        }

        // Update job status in the enrolled_jobs table
        const query = `
            UPDATE enrolled_jobs 
            SET status = $1
            WHERE job_id = $2 AND professional_id = $3
            RETURNING *;
        `;

        const { rows } = await db.query(query, [newStatus, jobId, professionalId]);

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Job not found" });
        }

        res.json({ success: true, message: "Job status updated successfully" });

    } catch (error) {
        console.error("Error updating job status:", error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.post('/request-payment', async (req, res) => {
    
        try {
            const { enrolledJobId, jobTitle, payAmount, bankName, accountNumber, accountName } = req.body;
            const professionalId = req.session.user.id;
    
            // Fetch job and company details
            const jobQuery = `
                SELECT j.company_id FROM enrolled_jobs ej
                JOIN jobs j ON ej.job_id = j.id
                WHERE ej.id = $1 AND ej.professional_id = $2
            `;
    
            const { rows } = await db.query(jobQuery, [enrolledJobId, professionalId]);
    
            if (rows.length === 0) {
                return res.status(403).json({ success: false, message: 'Unauthorized request.' });
            }
    
            const companyId = rows[0].company_id;
    
            // Insert into payment_requests
            const insertQuery = `
                INSERT INTO payment_requests (enrolled_job_id, professional_id, company_id, job_title, pay, bank_name, account_number, account_name)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            `;
    
            await db.query(insertQuery, [enrolledJobId, professionalId, companyId, jobTitle, payAmount, bankName, accountNumber, accountName]);
    
            // Update enrolled_jobs status
            /* await db.query(`UPDATE enrolled_jobs SET status = 'fully completed' WHERE id = $1`, [enrolledJobId]); */
    
            res.json({ success: true });
        } catch (error) {
            console.error('Error submitting payment request:', error);
            res.status(500).json({ success: false, message: 'Server error.' });
        }
});




/* app.post('/confirm-payment-received', async (req, res) => {
    const { paymentRequestId } = req.body;

    if (!paymentRequestId) {
        return res.json({ success: false, message: "Invalid request." });
    }

    try {
        const updateQuery = `
            UPDATE payment_requests 
            SET professional_receipt_status = TRUE 
            WHERE id = $1
        `;
        await db.query(updateQuery, [paymentRequestId]);
        

        return res.json({ success: true });
        
    } catch (error) {
        console.error("Error updating payment status:", error);
        return res.json({ success: false, message: "Database error." });
    }
}); */
app.post('/confirm-payment-received', async (req, res) => {
    const { paymentRequestId } = req.body;

    if (!paymentRequestId) {
        return res.json({ success: false, message: "Invalid request." });
    }

    try {
        // 1. Mark professional receipt status as TRUE
        await db.query(
            `UPDATE payment_requests 
             SET professional_receipt_status = TRUE 
             WHERE id = $1`,
            [paymentRequestId]
        );

        // 2. Fetch company_payment_status, enrolled_job_id, and professional_id
        const { rows } = await db.query(
            `SELECT company_payment_status, enrolled_job_id, professional_id 
             FROM payment_requests 
             WHERE id = $1`, 
            [paymentRequestId]
        );

        if (rows.length > 0) {
            const { company_payment_status, enrolled_job_id, professional_id } = rows[0];

            if (company_payment_status) {
                // 3. Fetch job_id and total_work_time from jobs
                const { rows: jobRows } = await db.query(
                    `SELECT j.id AS job_id, j.total_work_time 
                     FROM jobs j
                     INNER JOIN enrolled_jobs ej ON j.id = ej.job_id
                     WHERE ej.id = $1`,
                    [enrolled_job_id]
                );

                if (jobRows.length > 0) {
                    const { job_id, total_work_time } = jobRows[0];

                    // 4. Update job statuses
                    await db.query(
                        `UPDATE enrolled_jobs 
                         SET status = 'fully completed' 
                         WHERE id = $1`, 
                        [enrolled_job_id]
                    );

                    await db.query(
                        `UPDATE jobs 
                         SET status = 'completed' 
                         WHERE id = $1`, 
                        [job_id]
                    );

                    // 5. Update professional's total_hours_worked
                    await db.query(
                        `UPDATE users 
                         SET total_hours_worked = COALESCE(total_hours_worked, 0) + $1 
                         WHERE id = $2`,
                        [total_work_time, professional_id]
                    );
                }
            }
        }

        return res.json({ success: true });
        
    } catch (error) {
        console.error("Error updating payment status:", error);
        return res.json({ success: false, message: "Database error." });
    }
});




app.post("/company-mark-payment", async (req, res) => {
    try {
        const { paymentId } = req.body;
        await db.query("UPDATE payment_requests SET company_payment_status = TRUE WHERE id = $1", [paymentId]);
        res.sendStatus(200);
    } catch (error) {
        console.error("Error updating payment status:", error);
        res.sendStatus(500);
    }
});






// Start Server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
