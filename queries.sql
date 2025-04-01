-- TABLE 1: USERS (Handles Professionals, Companies, and Admins)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255), -- Used for both professionals and admins
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    location VARCHAR(255), -- Professionals only
    field_of_expertise VARCHAR(255), -- Professionals only
    years_of_experience INT CHECK (years_of_experience >= 0), -- Professionals only
    short_bio TEXT, -- Professionals only
    verification_document TEXT, -- Used for both professionals and companies
    industry_type VARCHAR(255), -- Companies only
    company_description TEXT, -- Companies only
    company_website VARCHAR(255), -- Companies only
    role VARCHAR(50) CHECK (role IN ('professional', 'company', 'admin')) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE, -- Admin approval required
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    total_hours_worked INT DEFAULT 0 CHECK (total_hours_worked >= 0)
);

-- TABLE 2: JOBS (Created by Companies)
CREATE TABLE jobs (
    id SERIAL PRIMARY KEY,
    company_id INT REFERENCES users(id) ON DELETE CASCADE, -- Company that posted the job
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    total_work_time INT CHECK (total_work_time >= 0), -- In hours
    pay DECIMAL(10,2) CHECK (pay >= 0),
    status VARCHAR(20) CHECK (status IN ('not started', 'in progress', 'completed')) DEFAULT 'not started',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- TABLE 3: JOB STAGES (Stores multiple stages for each job)
CREATE TABLE job_stages (
    id SERIAL PRIMARY KEY,
    job_id INT REFERENCES jobs(id) ON DELETE CASCADE,
    stage_name VARCHAR(255) NOT NULL,
    hours_required INT CHECK (hours_required >= 0) NOT NULL
);

-- TABLE 4: ENROLLED JOBS (Tracks Professionals working on jobs)
CREATE TABLE enrolled_jobs (
    id SERIAL PRIMARY KEY,
    job_id INT REFERENCES jobs(id) ON DELETE CASCADE,
    professional_id INT REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(30) CHECK (status IN ('in progress', 'completed (awaiting payment)', 'fully completed')) DEFAULT 'in progress',
    completion_date TIMESTAMP DEFAULT NULL
);

-- TABLE 5: APPLICATIONS (Professionals Applying for Jobs)
CREATE TABLE job_applications (
    id SERIAL PRIMARY KEY,
    job_id INT REFERENCES jobs(id) ON DELETE CASCADE,
    professional_id INT REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) CHECK (status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- TABLE 6: PAYMENT REQUESTS (Handles Payment for Completed Jobs)
CREATE TABLE payment_requests (
    id SERIAL PRIMARY KEY,
    enrolled_job_id INT REFERENCES enrolled_jobs(id) ON DELETE CASCADE,
    professional_id INT REFERENCES users(id) ON DELETE CASCADE,
    company_id INT REFERENCES users(id) ON DELETE CASCADE,
    job_title VARCHAR(255) NOT NULL,
    pay DECIMAL(10,2) CHECK (pay >= 0),
    bank_name VARCHAR(255) NOT NULL,
    account_number VARCHAR(20) NOT NULL,
    account_name VARCHAR(255) NOT NULL,
    company_payment_status BOOLEAN DEFAULT FALSE, -- TRUE when the company marks it as paid
    professional_receipt_status BOOLEAN DEFAULT FALSE, -- TRUE when the professional confirms receipt
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- TABLE 7: PROFESSIONAL WORK HISTORY (Stores Total Work Time)
CREATE TABLE professional_work_history (
    id SERIAL PRIMARY KEY,
    professional_id INT REFERENCES users(id) ON DELETE CASCADE,
    total_hours_worked INT DEFAULT 0 CHECK (total_hours_worked >= 0)
);
