import { Link, Navigate } from "react-router-dom";

export default function Home() {
  const token = localStorage.getItem("token");

  // If already logged in, go to dashboard
  if (token) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="
      bg-white 
      p-10 
      rounded-2xl 
      shadow-xl
      shadow-gray-200/60 
      max-w-md 
      w-full 
      text-center 
      space-y-6">
        <h1 className="text-3xl font-semibold tracking-tight text-gray-900">
          Auth System
        </h1>

        <p className="text-gray-600 leading-relaxed">
          A simple and secure authentication system built with
          React, Node.js, and MongoDB.
        </p>

        <div className="flex gap-4 justify-center">
          <Link
            to="/login"
            className="
            px-6 py-2
             bg-black
             text-white 
             rounded-lg
             hover:bg-gray-800
            active:scale-95 
             transition-all duration-200
             focus:outline-none
             focus:ring-2 focus:ring-black focus:ring-offset-2"
          >
            Login
          </Link>

          <Link
            to="/register"
            className="
            px-6 py-2 
            border border-gray-300         rounded-lg
             hover:bg-gray-100
             active:scale-95 transition-all duration-200
             focus:outline-none
             focus:ring-2 focus:ring-black focus:ring-offset-2"
          >
            Register
          </Link>
        </div>
      </div>
    </div>
  );
}
