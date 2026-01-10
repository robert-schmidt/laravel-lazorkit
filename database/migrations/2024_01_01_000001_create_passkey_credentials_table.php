<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('passkey_credentials', function (Blueprint $table) {
            // Primary key using ULID for ordering and uniqueness
            $table->ulid('id')->primary();

            // WebAuthn credential ID (base64url encoded, unique per credential)
            $table->string('credential_id', 255)->unique();

            // P-256 public key from WebAuthn (base64 encoded or JSON byte array)
            // Nullable because vanilla JS implementation may not always receive it
            $table->text('public_key')->nullable();

            // Solana smart wallet address (PDA controlled by LazorKit program)
            $table->string('smart_wallet_address', 64)->unique();

            // User agent for device identification (optional)
            $table->string('user_agent', 500)->nullable();

            // WebAuthn signature counter for replay protection
            $table->unsignedInteger('counter')->default(0);

            // Link to application's wallet user (if applicable)
            $table->string('wallet_address', 64)->nullable()->index();

            // Last time this credential was used for authentication
            $table->timestamp('last_used_at')->nullable();

            // Standard timestamps
            $table->timestamps();

            // Composite indexes for common queries
            $table->index('created_at');
            $table->index(['smart_wallet_address', 'last_used_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('passkey_credentials');
    }
};
