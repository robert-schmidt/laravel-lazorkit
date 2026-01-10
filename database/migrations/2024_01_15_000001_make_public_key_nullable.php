<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // Make public_key nullable if not already
        Schema::table('passkey_credentials', function (Blueprint $table) {
            $table->text('public_key')->nullable()->change();
        });

        // Clean up any credentials with invalid base58 wallet addresses
        // Base58 excludes: 0 (zero), O (uppercase o), I (uppercase i), l (lowercase L)
        // Valid characters: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
        DB::table('passkey_credentials')
            ->whereRaw("smart_wallet_address REGEXP '[0OIl]'")
            ->orWhereRaw("LENGTH(smart_wallet_address) < 32")
            ->orWhereRaw("LENGTH(smart_wallet_address) > 44")
            ->delete();
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Note: Cannot restore deleted credentials
        Schema::table('passkey_credentials', function (Blueprint $table) {
            $table->text('public_key')->nullable(false)->change();
        });
    }
};
