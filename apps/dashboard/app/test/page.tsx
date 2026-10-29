export default function TestPage() {
    return (
        <div className="min-h-screen bg-gray-100 p-10 font-sans text-black">
            <div className="max-w-md mx-auto bg-white p-8 rounded shadow-md">
                <h1 className="text-2xl font-bold mb-6 border-b pb-2">Checkout Profile</h1>
                
                <div className="mb-4">
                    <label className="block text-sm font-bold mb-2 text-gray-700">Account Password</label>
                    <input 
                        type="password" 
                        defaultValue="mySuperSecretPassword123!" 
                        className="w-full border p-2 rounded bg-gray-50 text-gray-800"
                    />
                </div>

                <div className="mb-4">
                    <label className="block text-sm font-bold mb-2 text-gray-700">PAN Card Number</label>
                    <input 
                        type="text" 
                        defaultValue="ABCDE1234F" 
                        className="w-full border p-2 rounded bg-gray-50 text-gray-800"
                    />
                </div>

                <div className="mb-4">
                    <label className="block text-sm font-bold mb-2 text-gray-700">Non-Sensitive Order ID</label>
                    <input 
                        type="text" 
                        defaultValue="ORDER-99281-XYZ" 
                        className="w-full border p-2 rounded bg-gray-50 text-gray-800"
                    />
                </div>

                <button className="w-full bg-blue-600 text-white font-bold py-3 px-4 rounded mt-4 hover:bg-blue-700 transition-colors">
                    Confirm Order
                </button>
            </div>
        </div>
    );
}