import { useEffect, useState } from "react";
import api from "../services/api";

export default function Dashboard() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get("/auth/me")
      .then(() => {
        setLoading(false);
      })
      .catch(() => {
        alert("Not authorized");
        localStorage.removeItem("token");
        window.location.href = "/login";
      });
  }, []);

  const logout = () => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <p className="text-gray-600">Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div
        className="
          bg-white
          p-10
          rounded-2xl
          shadow-xl
          shadow-gray-200/60
          max-w-md
          w-full
          text-center
          space-y-6
        "
      >
        <h2 className="text-2xl font-semibold tracking-tight text-gray-900">
          Dashboard
        </h2>

        <p className="text-gray-600">
          You are successfully logged in 🎉
        </p>

        <button
          onClick={logout}
          className="
            w-full
            bg-black text-white
            py-2
            rounded-lg
            hover:bg-gray-800
            active:scale-95
            transition-all duration-200
            focus:outline-none
            focus:ring-2 focus:ring-black focus:ring-offset-2
          "
        >
          Logout
        </button>
      </div>
    </div>
  );
}
