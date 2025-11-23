import React, { useState } from "react";
import "./Input.css";

export default function Input() {
  const [url, setUrl] = useState("");
  const [responseMessage, setResponseMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setResponseMessage("");

    // quick front-end validation
    if (!url || !/^https?:\/\//i.test(url)) {
      setResponseMessage("Please enter a valid URL starting with http:// or https://");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/predict-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await res.json();

      if (!res.ok) {
        setResponseMessage(data?.detail || "Server returned an error.");
      } else {
        // backend returns: { label: "Phishing" | "Legitimate", class_id: 0|1 }
        setResponseMessage(`Result: ${data.label}`);
      }
    } catch (err) {
      setResponseMessage(`Could not reach backend. ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-wrap">
      <div className="login-html">
        <h2 className="title">Enter the Website URL</h2>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-row">
            <div className="group">
              <label htmlFor="url" className="label">URL</label>
              <input
                id="url"
                type="text"
                className="input"
                placeholder="Enter the URL"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                autoComplete="off"
              />
            </div>
          </div>

          <div className="submit-button">
            <input
              type="submit"
              className="button"
              value={loading ? "Checking..." : "Submit"}
              disabled={loading}
            />
          </div>
        </form>

        {responseMessage && <p className="response-message">{responseMessage}</p>}
      </div>
    </div>
  );
}
