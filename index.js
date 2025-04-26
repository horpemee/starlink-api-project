const express = require('express');

const app = express();


app.use(express.json());

app.post('/activate-dish', async (req, res) => {
  const { kitId, coordinates } = req.body;

  try {
    const response = await fetch("https://api.starlink.com/kits/activate", {
      method: "POST",
      headers: {
        "Authorization": `Bearer YOUR_API_TOKEN`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        kit_id: kitId,
        coordinates: coordinates
      })
    });

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("Error activating dish:", error);
    res.status(500).json({ message: "Activation failed", error });
  }
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});